/**
 * The lane's OpenAI-compatible vendors (docs/relay-openai-compatible-vendors.md): vendors whose API key buys an
 * OpenAI Chat Completions compatible endpoint on one fixed host. Each one is a row of this table and nothing else:
 * the origin rule (`checkOfficialUpstream`), the control plane's vendor lists and paths, the stack configuration's
 * `vendor` enum, the credential form (`authorization: Bearer <api key>`), egress's route (`/<id>/…`), the panel and
 * the guide all read it. Adding the next vendor is one row here, the same row in egress (`vendors.go`), the published
 * copy (`vendors/openai-compatible-vendors.json`, which both are tested against) and Rust's validation table.
 *
 * Every row speaks `open_ai_chat` only, on `chatPath` under `pathPrefix`; billing reads the answer's Chat usage
 * (`@gray/protocol` `billedTokens`). `keptMembers` and `keptToolTypes` are the vendor's own request members and
 * tool types that keep a customer protection (docs/relay-request-changes.md P1 and P2) on top of Chat's: a relay
 * may not add or change them (a tool only removed). `storeOff` is whether the entry sends `store: false`
 * (OpenAI's stored completions; a vendor without them is sent no `store` member of Gray's).
 *
 * `catalogPrefix` is the Gray model ID prefix of the vendor's own models (OpenRouter's author names), what the panel
 * suggests; a route may still map any Gray model ID the vendor serves.
 */
export interface OpenAiCompatibleVendor {
  /** The vendor's id everywhere: lane, stack configuration, credential class, egress route `/<id>`. */
  readonly id: string;
  /** Its name on the panel and on Endpoints. */
  readonly name: string;
  /** The only host its calls reach. */
  readonly host: string;
  /** The base URL's path: every URL of the vendor's lane endpoint is under it. */
  readonly pathPrefix: string;
  /** The Chat Completions path, under `pathPrefix`. */
  readonly chatPath: string;
  /** Top-level request members a relay keeps as the customer sent them (P1, P2), besides Chat's. */
  readonly keptMembers: readonly string[];
  /** `/tools` entry types (by prefix) a relay may remove but not add or change. */
  readonly keptToolTypes: readonly string[];
  /** Whether every stack route of the vendor is sent `store: false` (P2: the vendor stores a completion otherwise). */
  readonly storeOff: boolean;
  /** The Gray model ID prefix of the vendor's own models. */
  readonly catalogPrefix: string;
}

/** One row; no vendor of the table has stored completions, so none is sent `store: false`. */
function row<const Id extends string>(
  id: Id,
  name: string,
  host: string,
  pathPrefix: string,
  chatPath: string,
  keptMembers: readonly string[],
  keptToolTypes: readonly string[],
  catalogPrefix: string,
) {
  return Object.freeze({ id, name, host, pathPrefix, chatPath, keptMembers: Object.freeze([...keptMembers]), keptToolTypes: Object.freeze([...keptToolTypes]), storeOff: false, catalogPrefix });
}

export const OPENAI_COMPATIBLE_VENDORS = Object.freeze([
  // ai.google.dev/gemini-api/docs/openai. `extra_body.google` carries `cached_content` (an explicit cache under the
  // account) and the vendor's own options.
  row("gemini", "Google Gemini", "generativelanguage.googleapis.com", "/v1beta/openai/", "/v1beta/openai/chat/completions", ["extra_body"], [], "google/"),
  // api-docs.deepseek.com: the reference's only server is https://api.deepseek.com.
  row("deepseek", "DeepSeek", "api.deepseek.com", "/", "/chat/completions", [], [], "deepseek/"),
  // platform.kimi.ai (international) and platform.kimi.com (China): a key works on its own region's host only.
  row("moonshot", "Moonshot Kimi", "api.moonshot.ai", "/v1/", "/v1/chat/completions", [], [], "moonshotai/"),
  row("moonshot_cn", "Moonshot Kimi (China)", "api.moonshot.cn", "/v1/", "/v1/chat/completions", [], [], "moonshotai/"),
  // docs.z.ai and docs.bigmodel.cn, pay-as-you-go (a Coding Plan key is the subscriber's own, not a relay's to sell).
  // A `web_search` tool makes the vendor search; `retrieval` reads a knowledge base under the account.
  row("zhipu", "Z.ai GLM", "api.z.ai", "/api/paas/v4/", "/api/paas/v4/chat/completions", [], ["web_search", "retrieval"], "z-ai/"),
  row("zhipu_cn", "Zhipu GLM (China)", "open.bigmodel.cn", "/api/paas/v4/", "/api/paas/v4/chat/completions", [], ["web_search", "retrieval"], "z-ai/"),
  // platform.minimax.io (international) and platform.minimax.cn (China).
  row("minimax", "MiniMax", "api.minimax.io", "/v1/", "/v1/chat/completions", [], [], "minimax/"),
  row("minimax_cn", "MiniMax (China)", "api.minimax.cn", "/v1/", "/v1/chat/completions", [], [], "minimax/"),
  // Alibaba Cloud Model Studio, OpenAI compatible mode, the shared Singapore and Beijing hosts. `enable_search` and
  // `search_options` make the vendor search; `enable_code_interpreter` runs code under the account.
  row("qwen", "Qwen (Model Studio)", "dashscope-intl.aliyuncs.com", "/compatible-mode/v1/", "/compatible-mode/v1/chat/completions", ["enable_search", "search_options", "enable_code_interpreter"], [], "qwen/"),
  row("qwen_cn", "Qwen (Model Studio China)", "dashscope.aliyuncs.com", "/compatible-mode/v1/", "/compatible-mode/v1/chat/completions", ["enable_search", "search_options", "enable_code_interpreter"], [], "qwen/"),
] as const satisfies readonly OpenAiCompatibleVendor[]);

/** An OpenAI-compatible vendor's id. */
export type OpenAiCompatibleVendorId = (typeof OPENAI_COMPATIBLE_VENDORS)[number]["id"];

/** The ids, in the table's order. */
export const OPENAI_COMPATIBLE_VENDOR_IDS: readonly OpenAiCompatibleVendorId[] = OPENAI_COMPATIBLE_VENDORS.map((v) => v.id);

/** The vendor's row, or undefined for another name. */
export function openAiCompatibleVendor(id: string): OpenAiCompatibleVendor | undefined {
  return (OPENAI_COMPATIBLE_VENDORS as readonly OpenAiCompatibleVendor[]).find((v) => v.id === id);
}

/** Whether `id` names an OpenAI-compatible vendor. */
export function isOpenAiCompatibleVendor(id: unknown): id is OpenAiCompatibleVendorId {
  return typeof id === "string" && openAiCompatibleVendor(id) !== undefined;
}

/**
 * Whether a stack route of `vendor` is sent `store: false` on Chat and Responses (docs/relay-request-changes.md P2):
 * OpenAI's and Codex's always, an OpenAI-compatible vendor's when its row says it stores a completion otherwise.
 */
export function stackStoreOff(vendor: string): boolean {
  return vendor === "openai" || vendor === "chatgpt_codex" || openAiCompatibleVendor(vendor)?.storeOff === true;
}

/**
 * Every vendor an account and a route of a relay stack may name (section 8): the three first vendors, then the table's.
 * `@gray/control` STACK_VENDORS, `@gray/lane-wire`'s stack schemas and `@gray/relay-connector` VENDORS are this list.
 */
export const LANE_STACK_VENDORS = Object.freeze(["anthropic", "openai", "chatgpt_codex", ...OPENAI_COMPATIBLE_VENDORS.map((v) => v.id)] as const);
export type LaneStackVendor = (typeof LANE_STACK_VENDORS)[number];
