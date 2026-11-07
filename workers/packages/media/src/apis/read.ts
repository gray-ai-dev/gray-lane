/**
 * Reading an upstream answer whole (crates/gray-gateway/src/inference.rs `Admission::read_body`):
 * within `limit` bytes (502 `upstream_body_limit`) and before the deadline (502
 * `upstream_body_incomplete`, as for a body cut off midway). A body that is not read to its end is
 * never billed or half-delivered.
 */
import { ApiError } from "@gray/errors";
import { readCapped } from "./egress.ts";

export async function readUpstream(response: Response, limit: number, deadlineMs: number): Promise<Uint8Array> {
  let bytes: Uint8Array | undefined;
  try {
    bytes = await readCapped(response, limit, deadlineMs);
  } catch {
    throw new ApiError(502, "upstream_body_incomplete");
  }
  if (bytes === undefined) throw new ApiError(502, "upstream_body_limit");
  return bytes;
}
