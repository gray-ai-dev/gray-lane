/**
 * Multipart forms of the upload APIs (crates/gray-gateway/src/apis/mod.rs `boundary`,
 * `receive_form`): the boundary read from the content type before the body is (a form without one
 * cannot be read: 400 `multipart_form_required`), then the parts in order, bounded in number and
 * label length.
 *
 * The media type is parsed by `content-type` (jshttp, RFC 7231 media types; the server uses
 * multer/mime); the body by the platform's `FormData` parser (the Fetch standard's
 * multipart/form-data parser; the server uses multer). One known difference: the platform decodes a
 * text field as UTF-8 with replacement characters, where the server refuses a text field that is
 * not valid UTF-8 (`invalid_form_field`).
 */
import { ApiError } from "@gray/errors";
import contentType from "content-type";
import { isControl } from "../text.ts";
import type { FormPart } from "./types.ts";

/** Most fields a multipart request may carry (mod.rs `MAX_PARTS`). */
export const MAX_PARTS = 64;
/** Longest field name, file name or content type (mod.rs `MAX_PART_LABEL`). */
export const MAX_PART_LABEL = 256;

/** `boundary`: the boundary of a multipart form's content type, or undefined. */
export function formBoundary(value: string | null): string | undefined {
  if (value === null) return undefined;
  try {
    const parsed = contentType.parse(value);
    if (parsed.type !== "multipart/form-data") return undefined;
    const boundary = parsed.parameters.boundary;
    return boundary === undefined || boundary.length === 0 ? undefined : boundary;
  } catch {
    return undefined;
  }
}

const invalidMultipart = () => new ApiError(400, "invalid_multipart");

/** A field name, file name or content type: non-empty, at most 256 bytes, no control character. */
function label(s: string): string | undefined {
  if (s.length === 0 || new TextEncoder().encode(s).length > MAX_PART_LABEL) return undefined;
  for (const ch of s) if (isControl(ch.codePointAt(0) as number)) return undefined;
  return s;
}

/**
 * `receive_form`: the fields of a whole multipart body, in order. Codes: `multipart_form_required`
 * (no boundary), `invalid_multipart` (unreadable, or a bad label), `too_many_form_fields`.
 */
export async function receiveForm(contentTypeValue: string | null, body: Uint8Array): Promise<FormPart[]> {
  if (formBoundary(contentTypeValue) === undefined) throw new ApiError(400, "multipart_form_required");
  let form: FormData;
  try {
    form = await new Response(body, { headers: { "content-type": contentTypeValue as string } }).formData();
  } catch {
    throw invalidMultipart();
  }
  const parts: FormPart[] = [];
  const utf8 = new TextEncoder();
  for (const [rawName, value] of form.entries()) {
    if (parts.length === MAX_PARTS) throw new ApiError(400, "too_many_form_fields");
    const name = label(rawName);
    if (name === undefined) throw invalidMultipart();
    if (typeof value === "string") {
      parts.push({ name, fileName: undefined, contentType: undefined, data: utf8.encode(value) });
      continue;
    }
    const file = value as File;
    const fileName = label(file.name);
    if (fileName === undefined) throw invalidMultipart();
    const type = file.type.length === 0 ? undefined : file.type;
    if (type !== undefined && new TextEncoder().encode(type).length > MAX_PART_LABEL) throw invalidMultipart();
    parts.push({ name, fileName, contentType: type, data: new Uint8Array(await file.arrayBuffer()) });
  }
  return parts;
}
