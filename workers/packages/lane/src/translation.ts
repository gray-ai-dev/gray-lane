/**
 * The confidential entry's translation of a request onto another text API, declared and replayable
 * (docs/design/lane-provider-routes.md section 10). The entry serves a model on an API it has no route of on that API
 * by translating the request onto an API on which the model has endpoint routes there, and its receipt names the
 * translation (`request.translated`). The bytes it forwards are
 *
 *     after( T( before(received) ) )
 *
 * - `before`: Gray's ops on the client's body, the `request.modified` events before `request.translated`
 *   (`gray-lane-rewrites-v1`, the client's API): the routing preference and the fallback models the gateway reads and
 *   takes out, which the translation would refuse as unknown fields. A Gemini client has none.
 * - `T`: the published translation the event names (`declared_in`). The body as serde_json reads it, translated from
 *   the event's `from` to its `to`, then, when the event names an `output_cap`, that cap written into it; written as
 *   serde_json writes it. `gray-lane-translation-v2`, the one the entry signs, is @gray/protocol `translateRequest` and
 *   `applyOutputCap` (the open-source code the gateway runs); `gray-lane-translation-v1` is the frozen copy
 *   @gray/protocol `translateRequestV1` and `applyOutputCapV1`, with v1's reading of a Gemini path.
 * - `after`: Gray's ops on the translated body, the `request.modified` events after `request.translated`, declared in
 *   the same policy (the upstream's API): the route's upstream model. A Gemini upstream names its model in the URL and
 *   has none.
 *
 * The translation is a function of the client's bytes and what the receipt carries, so a customer reproduces it
 * exactly: the stream mode is the client's own (its body's `stream`, a Gemini path's method), a Gemini client's model
 * is its path's, and the only ids a request translation makes up, those of a Gemini client's function calls, are
 * numbered by their position (`gm_<turn>_<n>`). Ids, timestamps and the rest of what a translation generates belong to
 * the answer, which the receipt names by the hash of the bytes the client got.
 *
 * A receipt replays only under the translation it names, never another. A change to what `translateRequest` or
 * `applyOutputCap` writes for some request is therefore a new translation: a new policy id (`gray-lane-translation-v3`,
 * in @gray/attest `TRANSLATION_POLICIES` and `TRANSLATIONS` below), the previous output frozen as v1 is (@gray/protocol
 * src/translate-v1), and a verifier that carries every id, since a receipt signed under the old code must still replay.
 * The translation vectors pin what each id writes: test/translation-vectors.test.ts in this package, over the corpus
 * and the bytes per id in test/fixtures/translation-vectors.json. A change to the live translation's output fails them
 * until it comes with a new id.
 */
import { get, isObject, readSerdeBytes, toJsonString, type Json, type JsonObject } from "@gray/json";
import { applyOutputCap, applyOutputCapV1, Refusal, translateRequest, translateRequestV1 } from "@gray/protocol";
import {
  TRANSLATED_APIS,
  TRANSLATION_POLICIES,
  requestModifiedEvent,
  requestTranslatedEvent,
  type RequestModifiedEvent,
  type TranslatedApi,
  type TranslationPolicyId,
} from "@gray/attest";
import { applyDeclaredChanges, type GrayRewriteOp } from "./changes.ts";
import { GRAY_LANE_REWRITES_V1, validateRewritePolicy, type LaneRewritePolicy } from "./policy.ts";
import { isLaneProtocol } from "./protocol.ts";
import { encodeUtf8 } from "./utf8.ts";

const MODEL_STRING = { kind: "string", min_bytes: 1, max_bytes: 512, forbid_control: true } as const;

/** The ops Gray may declare on a translated body, per upstream API: the route's upstream model. */
const TRANSLATED_BODY_RULES = {
  anthropic_messages: [
    { op: "set_member", path: "/model", value: MODEL_STRING },
    { op: "insert_member", path: "/model", value: MODEL_STRING },
  ],
  open_ai_chat: [
    { op: "set_member", path: "/model", value: MODEL_STRING },
    { op: "insert_member", path: "/model", value: MODEL_STRING },
  ],
  open_ai_responses: [
    { op: "set_member", path: "/model", value: MODEL_STRING },
    { op: "insert_member", path: "/model", value: MODEL_STRING },
  ],
};

/**
 * `gray-lane-translation-v1`: the ops Gray may declare on a translated body, per upstream API: the route's upstream
 * model (`set_member /model`, or `insert_member` for a body without one). The policy id is also what a
 * `request.translated` names as its translation (`declared_in`).
 */
export const GRAY_LANE_TRANSLATION_V1: LaneRewritePolicy = validateRewritePolicy({ id: "gray-lane-translation-v1", version: 1, protocols: TRANSLATED_BODY_RULES });
export const GRAY_LANE_TRANSLATION_V1_ID = "gray-lane-translation-v1" as const;
if (GRAY_LANE_TRANSLATION_V1.id !== GRAY_LANE_TRANSLATION_V1_ID) throw new Error("gray-lane-translation-v1's id");

/** `gray-lane-translation-v2`: v1's ops on the translated body, under the translation the entry signs now. */
export const GRAY_LANE_TRANSLATION_V2: LaneRewritePolicy = validateRewritePolicy({ id: "gray-lane-translation-v2", version: 2, protocols: TRANSLATED_BODY_RULES });
export const GRAY_LANE_TRANSLATION_V2_ID = "gray-lane-translation-v2" as const;
if (GRAY_LANE_TRANSLATION_V2.id !== GRAY_LANE_TRANSLATION_V2_ID) throw new Error("gray-lane-translation-v2's id");

/** The translation the entry signs, the live @gray/protocol code, and its policy. */
export const GRAY_LANE_TRANSLATION_ID: TranslationPolicyId = GRAY_LANE_TRANSLATION_V2_ID;
export const GRAY_LANE_TRANSLATION: LaneRewritePolicy = GRAY_LANE_TRANSLATION_V2;

/**
 * The names a translated request lists as dropped that no replay of the body gives: the client headers it does not
 * forward (@gray/translation `Translation.noteClientHeaders`: an Anthropic client's `anthropic-beta`). The receipt does
 * not carry headers, so a verifier accepts these beside the ones its replay finds.
 */
export const HEADER_DROPPED: readonly string[] = Object.freeze(["anthropic_beta"]);

/** Whether `api` is one of the four text APIs a translation names. */
export function isTranslatedApi(api: unknown): api is TranslatedApi {
  return typeof api === "string" && (TRANSLATED_APIS as readonly string[]).includes(api);
}

const GEMINI_GENERATION_PATH = /\/v1beta\/(?:models\/([^:]+)|([^:/]+\/[^:]+)):(generateContent|streamGenerateContent)$/;

/**
 * A Gemini generation path as the gateway serves it: `/v1beta/models/<model>` or `/v1beta/<org>/<model>`, then
 * `:generateContent` or `:streamGenerateContent` (@gray/lane-verify `protocolForEndpoint`). The model, percent-decoded,
 * and whether the method streams, or null for another path.
 */
export function geminiPathOf(endpoint: string): { readonly model: string; readonly stream: boolean } | null {
  const path = endpoint.split(/[?#]/, 1)[0] ?? "";
  const match = GEMINI_GENERATION_PATH.exec(path);
  if (match === null) return null;
  let model: string;
  try {
    model = decodeURIComponent(match[1] ?? match[2]!);
  } catch {
    return null;
  }
  if (model.length === 0) return null;
  return { model, stream: match[3] === "streamGenerateContent" };
}

/** gray-lane-translation-v1's reading of a Gemini path: the model as the path spells it. */
function geminiPathOfV1(endpoint: string): { readonly model: string; readonly stream: boolean } | null {
  const path = endpoint.split(/[?#]/, 1)[0] ?? "";
  const match = GEMINI_GENERATION_PATH.exec(path);
  if (match === null) return null;
  return { model: match[1] ?? match[2]!, stream: match[3] === "streamGenerateContent" };
}

/** One published translation: the ops it allows after it, how it reads a Gemini path, the request translation and the cap. */
interface Translation {
  readonly policy: LaneRewritePolicy;
  readonly geminiPath: (endpoint: string) => { readonly model: string; readonly stream: boolean } | null;
  readonly translate: (from: TranslatedApi, to: TranslatedApi, body: Json, pathModel: string | undefined, stream: boolean) => { readonly body: JsonObject; readonly dropped: readonly string[] };
  readonly applyOutputCap: (to: TranslatedApi, body: Json, cap: number) => readonly string[];
}

/** Every translation a receipt may name, by its id. Never change an entry's output; add an id. */
const TRANSLATIONS: Readonly<Record<TranslationPolicyId, Translation>> = {
  "gray-lane-translation-v1": { policy: GRAY_LANE_TRANSLATION_V1, geminiPath: geminiPathOfV1, translate: translateRequestV1, applyOutputCap: applyOutputCapV1 },
  "gray-lane-translation-v2": { policy: GRAY_LANE_TRANSLATION_V2, geminiPath: geminiPathOf, translate: translateRequest, applyOutputCap },
};
for (const id of TRANSLATION_POLICIES) if (TRANSLATIONS[id]?.policy.id !== id) throw new Error(`${id} has no translation`);

/** The translation `id` names, or null for an id this code does not carry. */
function translationOf(id: unknown): Translation | null {
  return typeof id === "string" && Object.hasOwn(TRANSLATIONS, id) ? TRANSLATIONS[id as TranslationPolicyId] : null;
}

/** What the replay needs besides the received bytes: the receipt's endpoint and its translation. */
export interface TranslationSpec {
  /** The receipt's `endpoint`: the path the client called. */
  readonly endpoint: string;
  readonly from: TranslatedApi;
  readonly to: TranslatedApi;
  /** The translation, by the id the receipt names (`request.translated.declared_in`); the entry signs `GRAY_LANE_TRANSLATION_ID`. */
  readonly declaredIn: TranslationPolicyId;
  /** The cap Gray wrote into the translated body, when it wrote one (`request.translated.output_cap`). */
  readonly outputCap?: bigint;
}

export type TranslationReplay =
  | {
      readonly ok: true;
      /** The bytes forwarded: `after(T(before(received)))`. */
      readonly forwarded: Uint8Array;
      /** The translation's own bytes, before the ops `after` declares. */
      readonly translated: Uint8Array;
      /** The client fields the translated body does not carry, sorted and each once. */
      readonly dropped: readonly string[];
    }
  | { readonly ok: false; readonly reason: string };

function fail(reason: string): TranslationReplay {
  return { ok: false, reason };
}

/**
 * `after(T(before(received)))` for ops given as Gray applies them. A refusal is a value, never a throw: an op outside
 * its policy, a body the translation refuses, a cap outside u32.
 */
export function translateDeclared(received: Uint8Array, spec: TranslationSpec, before: readonly GrayRewriteOp[], after: readonly GrayRewriteOp[]): TranslationReplay {
  const { from, to } = spec;
  const translation = translationOf(spec.declaredIn);
  if (translation === null) return fail(`${String(spec.declaredIn)} is not a translation this code carries`);
  if (!isTranslatedApi(from) || !isTranslatedApi(to) || from === to) return fail("a translation names two different text APIs");
  let client = received;
  if (before.length > 0) {
    if (!isLaneProtocol(from)) return fail(`Gray declares no op on a ${from} body`);
    const applied = applyDeclaredChanges(received, from, { grayOps: before, appends: [], policy: GRAY_LANE_REWRITES_V1 });
    if (!applied.ok) return fail(`the ops on the client's body do not apply (${applied.code})`);
    client = applied.forwarded;
  }
  let body: Json;
  try {
    body = readSerdeBytes(client).value;
  } catch {
    return fail("the client's body is not JSON");
  }
  let pathModel: string | undefined;
  let stream: boolean;
  if (from === "gemini") {
    const path = translation.geminiPath(spec.endpoint);
    if (path === null) return fail(`${spec.endpoint} is not a Gemini generation path`);
    pathModel = path.model;
    stream = path.stream;
  } else {
    stream = isObject(body) && get(body, "stream") === true;
  }
  let encoded: JsonObject;
  const dropped = new Set<string>();
  try {
    const translated = translation.translate(from, to, body, pathModel, stream);
    encoded = translated.body;
    for (const name of translated.dropped) dropped.add(name);
    if (spec.outputCap !== undefined) {
      if (spec.outputCap < 1n || spec.outputCap > 4_294_967_295n) return fail("the output cap is not 1 to 4294967295");
      for (const name of translation.applyOutputCap(to, encoded, Number(spec.outputCap))) dropped.add(name);
    }
  } catch (error) {
    if (error instanceof Refusal) return fail(`the translation refuses the client's body (${error.code} ${error.param})`);
    throw error;
  }
  const written = encodeUtf8(toJsonString(encoded));
  if (!written.ok) return fail("the translated body is not well-formed text");
  let forwarded = written.bytes;
  if (after.length > 0) {
    if (!isLaneProtocol(to)) return fail(`Gray declares no op on a ${to} body`);
    const applied = applyDeclaredChanges(written.bytes, to, { grayOps: after, appends: [], policy: translation.policy });
    if (!applied.ok) return fail(`the ops on the translated body do not apply (${applied.code})`);
    forwarded = applied.forwarded;
  }
  return { ok: true, forwarded, translated: written.bytes, dropped: [...dropped].sort() };
}

/** A receipt's `request.modified` events as ops, or null when one is not an op of `policy` with a value it carries. */
function opsOf(events: readonly RequestModifiedEvent[], policy: LaneRewritePolicy): GrayRewriteOp[] | null {
  const ops: GrayRewriteOp[] = [];
  for (const event of events) {
    if (typeof event !== "object" || event === null || event.type !== "request.modified" || event.declared_in !== policy.id) return null;
    if (event.op === "remove_member") {
      if (event.value !== undefined || event.value_sha256 !== undefined) return null;
      ops.push({ op: "remove_member", path: event.path });
    } else if (event.op === "set_member" || event.op === "insert_member") {
      // A value the event carries only as a digest cannot be replayed (`replayForwarded`).
      if (event.value === undefined || event.value_sha256 !== undefined) return null;
      ops.push({ op: event.op, path: event.path, value: event.value });
    } else {
      return null;
    }
  }
  return ops;
}

/**
 * The replay a verifier runs (docs/design/lane-provider-routes.md section 10): the receipt's ops before and after its
 * `request.translated`, each under its own policy, and the translation it names (`spec.declaredIn`, the event's
 * `declared_in`) and no other, over the client's `received` bytes. The answer's `forwarded` is what the receipt's
 * `request.forwarded` must hash to. Never throws.
 */
export function replayTranslated(received: Uint8Array, spec: TranslationSpec, before: readonly RequestModifiedEvent[], after: readonly RequestModifiedEvent[]): TranslationReplay {
  const translation = translationOf(spec.declaredIn);
  if (translation === null) return fail(`${String(spec.declaredIn)} is not a translation this code carries`);
  const pre = opsOf(before, GRAY_LANE_REWRITES_V1);
  if (pre === null) return fail("an op before the translation is not one gray-lane-rewrites-v1 declares with its value");
  const post = opsOf(after, translation.policy);
  if (post === null) return fail(`an op after the translation is not one ${translation.policy.id} declares with its value`);
  try {
    return translateDeclared(received, spec, pre, post);
  } catch {
    // The replay is a total function of an untrusted receipt: an internal invariant answers a refusal, never a throw.
    return fail("the translation could not be replayed");
  }
}

/** What the gateway signs for a translated attempt: the ops before, the `request.translated`, the ops after. */
export interface TranslationEvents {
  readonly before: readonly JsonObject[];
  readonly translated: JsonObject;
  readonly after: readonly JsonObject[];
}

/**
 * The gateway's half (lane mode, an endpoint route): the forwarded bytes of a translated attempt and the events that
 * declare them, from the same function a verifier replays. `dropped` is what the gateway's translation names (its
 * `x-gray-translation-dropped`), which may add HEADER_DROPPED to the replay's own.
 */
export function translatedForwarded(
  received: Uint8Array,
  spec: TranslationSpec,
  before: readonly GrayRewriteOp[],
  after: readonly GrayRewriteOp[],
  dropped: readonly string[],
): { readonly ok: true; readonly forwarded: Uint8Array; readonly translated: Uint8Array; readonly events: TranslationEvents } | { readonly ok: false; readonly reason: string } {
  const replay = translateDeclared(received, spec, before, after);
  if (!replay.ok) return replay;
  const translationPolicy = TRANSLATIONS[spec.declaredIn].policy;
  const events = (ops: readonly GrayRewriteOp[], policy: LaneRewritePolicy): JsonObject[] =>
    ops.map((op) => requestModifiedEvent({ op: op.op, path: op.path, ...(op.op === "remove_member" ? {} : { value: op.value }), declaredIn: policy.id }));
  return {
    ok: true,
    forwarded: replay.forwarded,
    translated: replay.translated,
    events: {
      before: events(before, GRAY_LANE_REWRITES_V1),
      translated: requestTranslatedEvent({
        from: spec.from,
        to: spec.to,
        dropped: [...new Set([...replay.dropped, ...dropped])],
        ...(spec.outputCap === undefined ? {} : { outputCap: spec.outputCap }),
        declaredIn: spec.declaredIn,
      }),
      after: events(after, translationPolicy),
    },
  };
}
