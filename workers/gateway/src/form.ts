import { ApiError } from "@gray/errors";
import { DEFERRED_HEAD_BYTES, type FormPart, MAX_PART_LABEL, MAX_PARTS, formBoundary } from "@gray/media";
import * as Multipasta from "multipasta";

/**
 * A multipart form's fields, as the model APIs' decoders read them (docs/design/standard-media-at-entry.md section
 * 2.3): read as it arrives by multipasta (a push parser that hands a file part on chunk by chunk), its text fields kept
 * and of each file only its head and its size. The confidential entry holds the form's bytes itself and sends them as
 * they are (lane/standard-api.ts `readEntryBody`), so nothing of a file is copied here. The decoders get each file as a
 * deferred part (@gray/media `FormPart`: its first DEFERRED_HEAD_BYTES, its size and a marker).
 *
 * The server reads a form whole (apis/mod.rs `receive_form`, multer) and holds every part. What this reads the same: the
 * field order, at most MAX_PARTS fields (`too_many_form_fields`), names, file names and content types of 1 to
 * MAX_PART_LABEL bytes without a control character, text fields in strict UTF-8 (`invalid_form_field`), anything
 * unreadable `invalid_multipart`. Different: the form's text fields together are bounded (`textBytes`, what a JSON body
 * of these APIs may hold); past it the form is refused as one no idle gateway could hold (`memoryRefusal`).
 */

/** A received form: its fields in order, and its bytes. */
export interface ReceivedForm {
  readonly parts: readonly FormPart[];
  /** The form's bytes. */
  readonly length: number;
}

export type FormRead = { readonly ok: true; readonly form: ReceivedForm } | { readonly ok: false; readonly error: ApiError };

export interface FormLimits {
  /** The text fields' bytes together (what a JSON body of these APIs holds). */
  readonly textBytes: number;
  /** REQUEST_BODY_MS. */
  readonly waitMs: number;
}

const invalidMultipart = () => new ApiError(400, "invalid_multipart");
const strictUtf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const encoder = new TextEncoder();

/** A field name, file name or content type: non-empty, at most MAX_PART_LABEL bytes, no control character (mod.rs `label`). */
function label(s: string | undefined): string | undefined {
  if (s === undefined || s.length === 0 || encoder.encode(s).length > MAX_PART_LABEL) return undefined;
  // char::is_control: C0, DEL and C1.
  for (const ch of s) {
    const c = ch.codePointAt(0)!;
    if (c < 0x20 || (c >= 0x7f && c <= 0x9f)) return undefined;
  }
  return s;
}

/** A marker for a deferred file: `GRAYDEFERRED` and 32 hex digits of fresh randomness (@gray/media `DEFERRED_MARKER`). */
function newMarker(): string {
  return `GRAYDEFERRED${crypto.randomUUID().replaceAll("-", "")}`;
}

/** One file part as it arrives: its head and its size. */
class FileWriter {
  readonly head = new Uint8Array(DEFERRED_HEAD_BYTES);
  headLength = 0;
  size = 0;

  readonly name: string;
  readonly fileName: string;
  readonly contentType: string | undefined;

  constructor(name: string, fileName: string, contentType: string | undefined) {
    this.name = name;
    this.fileName = fileName;
    this.contentType = contentType;
  }

  write(chunk: Uint8Array): void {
    if (this.headLength < DEFERRED_HEAD_BYTES) {
      const n = Math.min(DEFERRED_HEAD_BYTES - this.headLength, chunk.length);
      this.head.set(chunk.subarray(0, n), this.headLength);
      this.headLength += n;
    }
    this.size += chunk.length;
  }
}

type Event = { readonly kind: "field"; readonly info: Multipasta.PartInfo; readonly value: Uint8Array } | { readonly kind: "file"; readonly info: Multipasta.PartInfo } | { readonly kind: "chunk"; readonly chunk: Uint8Array | null } | { readonly kind: "error"; readonly error: Multipasta.MultipartError } | { readonly kind: "done" };

/** The refusal of a multipasta error. */
function refusal(error: Multipasta.MultipartError, limits: FormLimits): ApiError {
  if (error._tag === "ReachedLimit") {
    if (error.limit === "MaxParts") return new ApiError(400, "too_many_form_fields");
    if (error.limit === "MaxFieldSize") return memoryRefusal(limits.textBytes);
  }
  return invalidMultipart();
}

/**
 * 413 `request_body_limit` for a body no idle gateway could hold of one request (`limit` bytes it would
 * hold whole: a JSON body parsed whole, a form's text fields), with `limit_source` `gateway_memory`: the
 * server's words for a body its memory budget never takes (inference.rs `memory_refusal`, Refusal::Never).
 */
export function memoryRefusal(limit: number): ApiError {
  return new ApiError(413, "request_body_limit")
    .withMessage("The request body needs more memory than this Gray gateway gives one request. Send a smaller request (an agent can compact its conversation).")
    .withMeta("limit_bytes", BigInt(limit))
    .withMeta("limit_source", "gateway_memory");
}

/** Reads `request`'s multipart form within `limits`: its fields, and of each file its head and size. */
export async function readForm(request: Pick<Request, "headers" | "body">, limits: FormLimits): Promise<FormRead> {
  const contentTypeValue = request.headers.get("content-type");
  if (formBoundary(contentTypeValue) === undefined) return { ok: false, error: new ApiError(400, "multipart_form_required") };
  const header = request.headers.get("content-length");
  const declared = header !== null && /^[0-9]+$/.test(header) ? Number(header) : null;
  const events: Event[] = [];
  let parserError: Multipasta.MultipartError | null = null;
  const parser = Multipasta.make({
    headers: { "content-type": contentTypeValue! },
    // A part is a file when it names one (mod.rs: "Fields without a file name are UTF-8 text").
    isFile: (info) => info.filename !== undefined,
    maxParts: MAX_PARTS,
    maxFieldSize: limits.textBytes,
    onField: (info, value) => events.push({ kind: "field", info, value: value.slice() }),
    onFile: (info) => {
      events.push({ kind: "file", info });
      return (chunk) => events.push({ kind: "chunk", chunk });
    },
    onError: (error) => {
      parserError ??= error;
      events.push({ kind: "error", error });
    },
    onDone: () => events.push({ kind: "done" }),
  });
  const parts: (FormPart | FileWriter)[] = [];
  const finished = new Set<FileWriter>();
  let current: FileWriter | null = null;
  let textBytes = 0;
  let done = false;
  let length = 0;
  const fail = (error: ApiError): FormRead => {
    reader?.cancel().catch(() => {});
    return { ok: false, error };
  };
  /** Handles what the parser said about the last chunk; a refusal when the form is not one the server takes. */
  const drain = (): ApiError | null => {
    for (const event of events.splice(0)) {
      if (done) continue;
      switch (event.kind) {
        case "error":
          return refusal(event.error, limits);
        case "done":
          done = true;
          break;
        case "field": {
          const name = label(event.info.name);
          if (name === undefined) return invalidMultipart();
          // The text of a field without a file name is strict UTF-8 (FormPart::text, `invalid_form_field`).
          try {
            strictUtf8.decode(event.value);
          } catch {
            return new ApiError(400, "invalid_form_field");
          }
          textBytes += event.value.length;
          if (textBytes > limits.textBytes) return memoryRefusal(limits.textBytes);
          parts.push({ name, fileName: undefined, contentType: undefined, data: event.value });
          break;
        }
        case "file": {
          const name = label(event.info.name);
          const fileName = label(event.info.filename);
          if (name === undefined || fileName === undefined) return invalidMultipart();
          const raw = event.info.headers["content-type"];
          const type = Array.isArray(raw) ? raw.join(", ") : raw;
          if (type !== undefined && encoder.encode(type).length > MAX_PART_LABEL) return invalidMultipart();
          current = new FileWriter(name, fileName, type === undefined || type.length === 0 ? undefined : type);
          // A placeholder in the field order; the part is made once the file is whole.
          parts.push(current);
          break;
        }
        case "chunk": {
          const file: FileWriter | null = current;
          if (file === null) return invalidMultipart();
          if (event.chunk === null) {
            finished.add(file);
            current = null;
            break;
          }
          file.write(event.chunk);
          break;
        }
      }
    }
    return null;
  };
  let reader: ReadableStreamDefaultReader<Uint8Array> | null = request.body?.getReader() ?? null;
  let timer: ReturnType<typeof setTimeout> | null = null;
  const timeout = new Promise<"timeout">((resolve) => (timer = setTimeout(() => resolve("timeout"), limits.waitMs)));
  try {
    if (reader !== null) {
      for (;;) {
        let next: ReadableStreamReadResult<Uint8Array> | "timeout" | "broken";
        try {
          next = await Promise.race([reader.read(), timeout]);
        } catch {
          next = "broken";
        }
        if (next === "timeout") return fail(new ApiError(408, "request_body_timeout"));
        if (next === "broken") return fail(new ApiError(400, "request_body_incomplete"));
        if (next.done) break;
        length += next.value.length;
        if (declared !== null && length > declared) return fail(new ApiError(400, "request_body_incomplete"));
        if (done) continue;
        try {
          parser.write(next.value);
        } catch {
          // multipasta decodes `filename*` with decodeURIComponent, which throws on a malformed escape.
          return fail(invalidMultipart());
        }
        const refused = drain();
        if (refused !== null) return fail(refused);
      }
    }
    try {
      parser.end();
    } catch {
      return fail(invalidMultipart());
    }
    const refused = drain();
    if (refused !== null) return fail(refused);
    if (!done || parserError !== null) return fail(invalidMultipart());
  } finally {
    clearTimeout(timer);
  }
  if (parts.length > MAX_PARTS) return fail(new ApiError(400, "too_many_form_fields"));
  const out: FormPart[] = [];
  for (const part of parts) {
    if (!(part instanceof FileWriter)) {
      out.push(part);
      continue;
    }
    if (!finished.has(part)) return fail(invalidMultipart());
    // A file no longer than its head is held as it is; any other is deferred: its head, its size and a marker.
    if (part.size <= DEFERRED_HEAD_BYTES) {
      out.push({ name: part.name, fileName: part.fileName, contentType: part.contentType, data: part.head.slice(0, part.size) });
      continue;
    }
    out.push({ name: part.name, fileName: part.fileName, contentType: part.contentType, data: part.head.slice(0, part.headLength), size: part.size, marker: newMarker() });
  }
  return { ok: true, form: { parts: out, length } };
}
