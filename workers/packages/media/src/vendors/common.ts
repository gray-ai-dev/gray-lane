/**
 * The helpers every vendor module shares (crates/gray-media-adapters/src/vendors/mod.rs).
 */
import type { Json, JsonObject } from "@gray/json";
import { invalid, malformed, unsupportedOperation, vendorError } from "../error.ts";
import { hasControlOrWhitespace, utf8Length } from "../text.ts";
import { httpError, isSuccess, parseErrorJson } from "../util.ts";
import { OPERATION_DEBUG, type HttpCall, type Operation, type Parsed, type Usage, type VendorJob, usageOf } from "../types.ts";

/** A built call plus the units it asks for (creation operations only). */
export interface Built {
  readonly call: HttpCall;
  readonly units: Usage | undefined;
}

export function built(call: HttpCall, units: Usage): Built {
  return { call, units };
}

export function step(call: HttpCall): Built {
  return { call, units: undefined };
}

export function unsupportedOp(vendor: string, op: Operation): Error {
  return unsupportedOperation(`${vendor} does not support ${OPERATION_DEBUG[op]}`);
}

export function post(path: string, body: JsonObject): HttpCall {
  return { method: "POST", path, query: [], headers: [["content-type", "application/json"]], body, response: "json" };
}

export function get(path: string, query: [string, string][]): HttpCall {
  return { method: "GET", path, query, headers: [], body: null, response: "json" };
}

export function needJob(job: VendorJob | undefined): VendorJob {
  if (job === undefined) throw invalid("this operation needs the vendor job");
  return job;
}

/**
 * `check_status`: a non-2xx status is the vendor's own error when `extract` recognises the body,
 * else a generic HTTP error.
 */
export function checkStatus(status: number, body: Uint8Array, extract: (v: Json) => [string, string] | undefined): void {
  if (isSuccess(status)) return;
  const parsed = parseErrorJson(body);
  const found = parsed === undefined ? undefined : extract(parsed);
  if (found !== undefined) throw vendorError(status, found[0], found[1]);
  throw httpError(status, body);
}

/** One image in an OpenAI images response: inline base64, or a vendor URL the gateway downloads and inlines. */
export type ImageOut = { readonly kind: "b64"; readonly data: string } | { readonly kind: "url"; readonly url: string };

/** `opaque_url`: a vendor URL handed to the gateway, non-empty, at most 16 KiB, no whitespace or control characters. */
export function opaqueUrl(what: string, v: Json | undefined): string {
  if (typeof v === "string" && v.length > 0 && utf8Length(v) <= 16 * 1024 && !hasControlOrWhitespace(v)) return v;
  throw malformed(`${what} is missing or invalid`);
}

/** `image_out`: a `data:` URI becomes inline base64, anything else is an opaque URL. */
export function imageOut(what: string, v: Json | undefined): ImageOut {
  const s = opaqueUrl(what, v);
  if (s.startsWith("data:")) {
    const rest = s.slice(5);
    const at = rest.indexOf(";base64,");
    if (at >= 0) return { kind: "b64", data: rest.slice(at + ";base64,".length) };
  }
  return { kind: "url", url: s };
}

/**
 * `images`: the OpenAI images answer. Units are what was delivered, capped by the vendor's own count
 * when it reports one. Zero images is an error: nothing is billable and the customer gets nothing.
 */
export function images(created: bigint, out: readonly ImageOut[], vendorCount: bigint | undefined, emptyCode: string, emptyMessage: string): Parsed {
  const delivered = BigInt(out.length);
  const units = vendorCount === undefined ? delivered : vendorCount < delivered ? vendorCount : delivered;
  if (units === 0n) throw vendorError(200, emptyCode, emptyMessage);
  const data: Json[] = out.slice(0, Number(units)).map((i): Json => (i.kind === "b64" ? { b64_json: i.data } : { url: i.url }));
  const usage = usageOf("images", units);
  return {
    kind: "images",
    response: { created, data },
    usage: vendorCount === undefined ? usage : { ...usage, raw: { images: vendorCount } },
  };
}

/**
 * `video_shape`: a video `WxH` as (short side, aspect ratio) when its ratio is within 1% of one of
 * `ratios` (vendors list ratios, not exact pixels, and common sizes such as 854x480 are not exact
 * reductions).
 */
export function videoShape(w: number, h: number, ratios: readonly string[]): [number, string] | undefined {
  const actual = w / h;
  const r = ratios.find((r) => {
    const [a, b] = r.split(":") as [string, string];
    return Math.abs(actual / (Number(a) / Number(b)) - 1) <= 0.01;
  });
  return r === undefined ? undefined : [Math.min(w, h), r];
}

export { isSuccess };
