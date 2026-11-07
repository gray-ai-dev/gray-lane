/**
 * Rule B, the choosing half: a relay registers template texts with ids ahead of time, and its policy
 * module chooses ids only. The module never supplies text, so the only text that can ever be
 * appended to a customer's request is text the relay registered before the request existed and Gray
 * can show the customer.
 *
 * A template says where it may go and for which protocols:
 *
 *     { id, text, positions: Position[], protocols: Protocol[], maxTextBytes }
 *
 * `positions` and `protocols` are sets, and the pair is resolved by the request's protocol: for each
 * protocol the template declares, **exactly one** of its positions must exist for that protocol.
 * That keeps the choice of position deterministic without the module naming a position (a template
 * that could go to two places would make "the receipt says where" ambiguous, and a module that
 * could name the position could steer the request). One template can therefore serve
 * `system_end` for Anthropic and `instructions_after` for Chat Completions at once; to offer the
 * same text at two positions of one protocol, the relay registers two ids.
 *
 * Every rule of review.md section 3.5 that belongs here is enforced here rather than trusted to the
 * module: text must be non-empty, well-formed UTF-16, within the template's own `maxTextBytes`, and
 * the selection must fit `maxItems` and `maxTotalBytes`. The reason code vocabulary the module may
 * return is closed; an unknown string is a schema failure, not something that reaches a customer or
 * a store.
 */
import { refusal, type Refusal } from "./refusal.ts";
import { isLaneProtocol, isPosition, isPositionForProtocol, type LaneProtocol, type Position } from "./protocol.ts";
import { utf8Length } from "./utf8.ts";
import type { AppendedText } from "./append.ts";

/** A text a relay has registered, and where it may be appended. */
export interface RelayTemplate {
  readonly id: string;
  readonly text: string;
  readonly positions: readonly Position[];
  readonly protocols: readonly LaneProtocol[];
  readonly maxTextBytes: number;
}

/** Why a registry is refused. */
export type TemplateRefusalCode =
  | "invalid_template_id"
  | "empty_text"
  | "invalid_text"
  | "invalid_position"
  | "invalid_protocol"
  | "position_protocol_mismatch"
  | "ambiguous_position"
  | "invalid_limit"
  | "template_too_large"
  | "duplicate_template";

/** Why a selection is refused. */
export type SelectionRefusalCode =
  | "unknown_protocol"
  | "policy_output_invalid"
  | "unknown_template"
  | "duplicate_template"
  | "template_protocol"
  | "template_position"
  | "too_many_items"
  | "append_limit";

/** A closed reason code a policy module may give for blocking a request. */
export type PolicyReasonCode = "blocked" | "append_limit";

/** The module's whole vocabulary for refusing a request. */
export const POLICY_REASON_CODES: readonly PolicyReasonCode[] = ["blocked", "append_limit"];

/** Whether `value` is one of the closed reason codes. */
export function isPolicyReasonCode(value: unknown): value is PolicyReasonCode {
  return value === "blocked" || value === "append_limit";
}

/** What a signed policy module answers, and all it can say. */
export type PolicyOutput =
  | { readonly decision: "allow"; readonly templates: readonly string[] }
  | { readonly decision: "block"; readonly reason_code: PolicyReasonCode };

/** The default total of appended bytes one request may carry (review.md section 3.5, item 3: 8 KiB). */
export const DEFAULT_MAX_TOTAL_BYTES = 8192;

/** The default number of appends one request may carry (review.md section 3.5, item 3: 3). */
export const DEFAULT_MAX_ITEMS = 3;

/** The longest template id, and the characters it may hold: it reaches receipts, so it is plain. */
const TEMPLATE_ID = /^[A-Za-z0-9_.:-]{1,128}$/;

/** What a registry carries besides its templates. */
export interface TemplateRegistryOptions {
  readonly maxTotalBytes?: number;
  readonly maxItems?: number;
}

/** The relay's registered templates, checked once when the registry is built. */
export interface TemplateRegistry {
  readonly ok: true;
  readonly templates: readonly RelayTemplate[];
  readonly maxTotalBytes: number;
  readonly maxItems: number;
  /** The template with this id, or `undefined`. */
  template(id: string): RelayTemplate | undefined;
}

/**
 * Build a registry, refusing anything the lane's rules cannot express (each code names the rule).
 * `maxTotalBytes` and `maxItems` are the host's per-request caps: the gateway reads them from
 * @gray/config and passes them here, so this package keeps no tunables of its own.
 */
export function createTemplateRegistry(
  templates: readonly RelayTemplate[],
  options: TemplateRegistryOptions = {},
): TemplateRegistry | Refusal<TemplateRefusalCode> {
  const maxTotalBytes = options.maxTotalBytes ?? DEFAULT_MAX_TOTAL_BYTES;
  const maxItems = options.maxItems ?? DEFAULT_MAX_ITEMS;
  if (!isPositiveInteger(maxTotalBytes)) return refusal("invalid_limit", "maxTotalBytes is not a positive integer");
  if (!isPositiveInteger(maxItems)) return refusal("invalid_limit", "maxItems is not a positive integer");
  if (!Array.isArray(templates)) return refusal("invalid_limit", "the templates are not an array");

  const byId = new Map<string, RelayTemplate>();
  for (const template of templates) {
    if (typeof template?.id !== "string" || !TEMPLATE_ID.test(template.id)) {
      return refusal("invalid_template_id", "a template id is empty or holds characters other than [A-Za-z0-9_.:-]");
    }
    if (byId.has(template.id)) return refusal("duplicate_template", `two templates have the id ${template.id}`);
    if (typeof template.text !== "string" || template.text.length === 0) {
      return refusal("empty_text", `template ${template.id} has no text`);
    }
    if (!template.text.isWellFormed()) {
      return refusal("invalid_text", `template ${template.id} holds a lone surrogate, which has no UTF-8 bytes`);
    }
    if (!isPositiveInteger(template.maxTextBytes)) {
      return refusal("invalid_limit", `template ${template.id} has no positive maxTextBytes`);
    }
    const textBytes = utf8Length(template.text);
    if (textBytes > template.maxTextBytes) {
      return refusal("template_too_large", `template ${template.id} is ${textBytes} bytes, over its ${template.maxTextBytes}`);
    }
    if (!Array.isArray(template.positions) || template.positions.length === 0) {
      return refusal("invalid_position", `template ${template.id} names no position`);
    }
    const positions: Position[] = [];
    for (const position of template.positions) {
      if (!isPosition(position)) return refusal("invalid_position", `template ${template.id} names an unknown position`);
      if (positions.includes(position)) return refusal("invalid_position", `template ${template.id} names a position twice`);
      positions.push(position);
    }
    if (!Array.isArray(template.protocols) || template.protocols.length === 0) {
      return refusal("invalid_protocol", `template ${template.id} names no protocol`);
    }
    const protocols: LaneProtocol[] = [];
    for (const protocol of template.protocols) {
      if (!isLaneProtocol(protocol)) return refusal("invalid_protocol", `template ${template.id} names a protocol outside the lane`);
      if (protocols.includes(protocol)) return refusal("invalid_protocol", `template ${template.id} names a protocol twice`);
      protocols.push(protocol);
    }
    for (const position of positions) {
      if (!protocols.some((protocol) => isPositionForProtocol(protocol, position))) {
        return refusal("position_protocol_mismatch", `template ${template.id} names ${position}, which none of its protocols has`);
      }
    }
    // Exactly one position per declared protocol, both halves: a protocol this template has no
    // position for could never be served by it (the error would otherwise surface only at selection,
    // as `template_position`), and two positions would make the receipt's position ambiguous.
    for (const protocol of protocols) {
      const usable = positions.filter((position) => isPositionForProtocol(protocol, position));
      if (usable.length === 0) {
        return refusal("position_protocol_mismatch", `template ${template.id} declares ${protocol} but has no position for it`);
      }
      if (usable.length > 1) {
        return refusal("ambiguous_position", `template ${template.id} has ${usable.length} positions for ${protocol}, so its position would not be determined`);
      }
    }
    byId.set(template.id, { ...template, positions, protocols });
  }
  return {
    ok: true,
    templates: [...byId.values()],
    maxTotalBytes,
    maxItems,
    template: (id: string) => byId.get(id),
  };
}

/**
 * The position a template uses for a request of `protocol`: the one position of its `positions`
 * that `protocol` has, or `undefined` when it has none or more than one.
 */
export function positionOf(template: RelayTemplate, protocol: LaneProtocol): Position | undefined {
  if (!template.protocols.includes(protocol)) return undefined;
  const usable = template.positions.filter((position) => isPositionForProtocol(protocol, position));
  return usable.length === 1 ? usable[0] : undefined;
}

/** What the module decided, as far as the host can carry it out. */
export type Selection =
  | { readonly ok: true; readonly kind: "append"; readonly appends: readonly AppendedText[] }
  | { readonly ok: true; readonly kind: "block"; readonly reason_code: PolicyReasonCode };

/**
 * Check a policy module's answer against the registry and turn it into the appends `F` applies, in
 * the order the module listed the ids (that order is the order they are appended in, and the order
 * the receipt records). A `block` decision is not a refusal — it is a policy outcome the host
 * answers with the lane's fixed refusal — but a malformed answer, an unknown id, a duplicate id, a
 * template the relay did not register for this protocol, or a selection over the caps is.
 */
export function selectAppends(
  registry: TemplateRegistry,
  protocol: LaneProtocol,
  output: PolicyOutput,
): Selection | Refusal<SelectionRefusalCode> {
  if (!isLaneProtocol(protocol)) return refusal("unknown_protocol", "the protocol is not one of the lane's three");
  if (typeof output !== "object" || output === null || Array.isArray(output)) {
    return refusal("policy_output_invalid", "the policy output is not an object");
  }
  if (output.decision === "block") {
    if (!isPolicyReasonCode(output.reason_code)) {
      return refusal("policy_output_invalid", "the policy output blocks with a reason code outside the closed set");
    }
    return { ok: true, kind: "block", reason_code: output.reason_code };
  }
  if (output.decision !== "allow") return refusal("policy_output_invalid", "the policy output is neither allow nor block");
  if (!Array.isArray(output.templates)) return refusal("policy_output_invalid", "the allow decision names no list of template ids");
  if (output.templates.length > registry.maxItems) {
    return refusal("too_many_items", `the selection names ${output.templates.length} templates, over the ${registry.maxItems} allowed`);
  }

  const appends: AppendedText[] = [];
  const chosen = new Set<string>();
  let totalBytes = 0;
  for (const id of output.templates) {
    if (typeof id !== "string") return refusal("policy_output_invalid", "a template id in the selection is not a string");
    const template = registry.template(id);
    if (template === undefined) return refusal("unknown_template", `the selection names ${id}, which the relay did not register`);
    if (chosen.has(id)) return refusal("duplicate_template", `the selection names ${id} twice`);
    chosen.add(id);
    const position = positionOf(template, protocol);
    if (position === undefined) {
      if (!template.protocols.includes(protocol)) {
        return refusal("template_protocol", `template ${id} is not registered for this protocol`);
      }
      return refusal("template_position", `template ${id} has no single position for this protocol`);
    }
    const bytes = utf8Length(template.text);
    totalBytes += bytes;
    if (totalBytes > registry.maxTotalBytes) {
      return refusal("append_limit", `the selection appends ${totalBytes} bytes, over the ${registry.maxTotalBytes} allowed`);
    }
    appends.push({ templateId: id, position, text: template.text });
  }
  return { ok: true, kind: "append", appends };
}

function isPositiveInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}
