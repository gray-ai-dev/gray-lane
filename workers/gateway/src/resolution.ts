import { ApiError } from "@gray/errors";
import { compareUtf8 } from "@gray/json";
import { type CanonicalRequest, type Protocol, endpointPath, isGeneration, reasoningRequested, structured } from "@gray/protocol";
import { type TranslationPolicy, protocolTitle } from "@gray/translation";
import { chatFor, type GatewaySnapshot, type ModeCapabilities, type RouteRecord, routeServes } from "./snapshot.ts";

/**
 * What a request for a model without a usable native route is told (crates/gray-gateway/src/
 * model_resolution.rs `unrouted`): a capability no live route of the model proved; a model served
 * through another API, and which; a model that has providers but none verified now; or a model
 * Gray does not have. Not ported: the "did you mean" suggestions, which need the live catalog.
 */

const NO_PROVIDER_RETRY_SECONDS = 60n;

/** The generation APIs, in the order their paths are listed (model_resolution.rs `GENERATION`). */
const GENERATION: readonly Protocol[] = ["open_ai_chat", "open_ai_responses", "anthropic_messages", "gemini"];

function noProvider(model: string): ApiError {
  return new ApiError(503, "no_available_provider")
    .withMessage(`No verified provider can serve \`${model}\` right now. Gray re-checks providers continuously; retry in a minute, or choose another model.`)
    .withMeta("limit_source", "provider_availability")
    .withRetryAfter(NO_PROVIDER_RETRY_SECONDS);
}

function andList(items: readonly string[]): string {
  if (items.length <= 1) return items.join("");
  return `${items.slice(0, -1).join(", ")} and ${items.at(-1)}`;
}

/** The capability a request carrying images or files needs. */
const IMAGE_INPUT = "image or file input";

/**
 * What a buffered (`stream: false`) request needs of a route: that it does not serve streamed requests only
 * (model_resolution.rs `BUFFERED_ANSWERS`). A combination refusal never names it: a route proves a capability for
 * buffered requests only when it answers them (`chatFor`), so it is never what keeps the other needs apart.
 */
const BUFFERED_ANSWERS = "non-streamed answers";

/**
 * `content_param`: the request field of `protocol` that carries the conversation, images and files
 * included: Gemini's `contents`, the Responses API's `input`, the Chat and Messages APIs' `messages`.
 */
function contentParam(protocol: Protocol): string {
  if (protocol === "gemini") return "contents";
  if (protocol === "open_ai_responses") return "input";
  return "messages";
}

/**
 * 400 `unsupported_capability` when the request needs what no live route proved in the request's mode, alone or
 * together. `protocol` is the client's, whose field carrying the images a refusal of image input names;
 * `imagesElsewhere`, the other paths the model takes images through, named when image input is what
 * no route here proved.
 */
export function missingCapability(model: string, protocol: Protocol, routes: readonly Pick<RouteRecord, "capabilities">[], request: CanonicalRequest, mediaUnknown: boolean, imagesElsewhere: readonly string[]): ApiError | null {
  const images = mediaUnknown || request.messages.some((m) => m.content.some((c) => c.type === "image_url" || c.type === "input_image" || c.type === "file"));
  // Each need's `proved` reads the route and the chat capabilities it proved in the request's mode (`chatFor`).
  type Need = { needed: boolean; name: string; param: string; proved: (r: Pick<RouteRecord, "capabilities">, chat: ModeCapabilities) => boolean };
  const needs: Need[] = [
    { needed: request.stream, name: "streaming", param: "stream", proved: (r) => r.capabilities.streaming },
    // A route that serves streamed requests only (decision (a) of 2026-10-23) takes no buffered one. Asked of the
    // routes only when one of them serves streamed requests only: every other route proves it, and a refusal over
    // no route names what the request needs beyond a plain buffered answer, as before.
    { needed: !request.stream && routes.some((r) => r.capabilities.streamedOnly === true), name: BUFFERED_ANSWERS, param: "stream", proved: (r) => r.capabilities.streamedOnly !== true },
    { needed: request.tools.length > 0, name: "tool calling", param: "tools", proved: (_, chat) => chat.tools },
    { needed: request.response_format !== null && structured(request.response_format), name: "structured output (JSON schema)", param: "response_format", proved: (_, chat) => chat.structuredOutput },
    { needed: request.reasoning !== null && reasoningRequested(request.reasoning), name: "reasoning", param: "reasoning", proved: (_, chat) => chat.reasoning },
    { needed: images, name: IMAGE_INPUT, param: contentParam(protocol), proved: (_, chat) => chat.vision },
  ];
  const proves = (n: Need, r: Pick<RouteRecord, "capabilities">) => n.proved(r, chatFor(r.capabilities, request.stream));
  const unproved = needs.filter((n) => n.needed && !routes.some((r) => proves(n, r)));
  if (unproved.length > 0) {
    const names = unproved.map((n) => n.name);
    let error = new ApiError(400, "unsupported_capability")
      .withMessage(`No verified provider of \`${model}\` supports ${names.join(" or ")} through this API right now. Send the request without it, or choose another model.`)
      .withParam(unproved[0]!.param)
      .withMeta("capabilities", names)
      .withHelp("models");
    if (names.includes(IMAGE_INPUT) && imagesElsewhere.length > 0) {
      error = error
        .withMessage(
          `No verified provider of \`${model}\` supports ${names.join(" or ")} through this API right now. \`${model}\` takes images through ${imagesElsewhere.join(", ")}. Send the request there or without the images, or choose another model.`,
        )
        .withMeta("paths", [...imagesElsewhere]);
    }
    return error;
  }
  const needed = needs.filter((n) => n.needed && n.name !== BUFFERED_ANSWERS);
  if (needed.length < 2 || routes.some((r) => needed.every((n) => proves(n, r)))) return null;
  const names = needed.map((n) => n.name);
  return new ApiError(400, "unsupported_capability")
    .withMessage(
      `No verified provider of \`${model}\` supports ${andList(names)} together through this API right now: each is supported by some provider, but none supports them all. Send the request without one of them, or choose another model.`,
    )
    .withParam(needed[0]!.param)
    .withMeta("capabilities", names)
    .withMeta("combination", true)
    .withHelp("models");
}

/**
 * `policy`: the operator's translation policy; an API it lets reach a served one is named as a path
 * the model can be called through, as one that serves it natively is.
 */
export function unrouted(snapshot: GatewaySnapshot, request: CanonicalRequest, protocol: Protocol, nowMs: number, mediaUnknown: boolean, policy?: TranslationPolicy): ApiError {
  const model = request.model;
  const routes = snapshot.routes.filter((r) => r.model === model);
  const live = routes.filter((r) => routeServes(r.expiresAt, nowMs));
  // The upstream protocols that could serve a request through `protocol`: itself, and the translation
  // targets the operator allows for the model.
  const targets: Protocol[] = [protocol, ...(policy?.upstreams(model, protocol) ?? [])];
  const here = live.filter((r) => targets.includes(r.protocol));
  if (here.length > 0) {
    // Where else the model takes images: an image edits route, or a generation route of another API that
    // proved image input (model_resolution.rs on main), each path once, in order.
    const elsewhere = [
      ...new Set(
        live
          .filter((r) => r.protocol !== protocol && (r.protocol === "open_ai_image_edits" || (isGeneration(r.protocol) && r.capabilities.vision)))
          .map((r) => `POST ${endpointPath(r.protocol, model, false)}`),
      ),
    ].sort(compareUtf8);
    return missingCapability(model, protocol, here, request, mediaUnknown, elsewhere) ?? noProvider(model);
  }
  // A provider maps the model on this API (or on a translation target), but its route is not verified
  // now: a pause, not a wrong API. An image generation mapping through the Gemini adapter maps its model
  // on the Gemini API too (`GatewaySnapshot.mapped`). A snapshot without the pairs says it by its routes.
  const mapped = snapshot.mapped;
  const mappedHere = mapped !== undefined ? mapped.some((m) => m.model === model && targets.includes(m.protocol)) : routes.some((r) => r.protocol === protocol);
  if (mappedHere) return noProvider(model);
  const served = new Set(live.map((r) => r.protocol));
  const paths: string[] = [];
  for (const client of [...GENERATION, ...[...served].filter((p) => !GENERATION.includes(p))]) {
    const reachable = served.has(client) || (GENERATION.includes(client) && (policy?.upstreams(model, client)?.some((u) => served.has(u)) ?? false));
    if (reachable && client !== protocol) paths.push(`POST ${endpointPath(client, model, false)}`);
  }
  if (paths.length > 0) {
    return new ApiError(400, "wrong_api_for_model")
      .withMessage(`The model \`${model}\` is not served through ${protocolTitle(protocol)}. Call it through: ${paths.join(", ")}.`)
      .withMeta("paths", paths)
      .withHelp(null);
  }
  if (routes.length > 0 || (mapped?.some((m) => m.model === model) ?? false)) return noProvider(model);
  return new ApiError(404, "model_not_found").withMessage(`The model \`${model}\` does not exist on Gray.`).withMeta("suggestions", []);
}
