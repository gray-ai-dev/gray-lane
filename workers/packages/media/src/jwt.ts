/**
 * Kling's request token: a JWT (HS256) signed with the secret key (crates/gray-media-adapters/src/jwt.rs,
 * https://kling.ai/document-api/api/get-started/authentication). HMAC-SHA256 is @noble/hashes',
 * base64url @scure/base's; the claims are written as serde_json writes them (keys in byte order).
 */
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha2";
import { toJsonString } from "@gray/json";
import { base64urlnopad } from "@scure/base";
import { invalidCredential } from "./error.ts";
import { rustTrim, utf8Length } from "./text.ts";
import { MAX_CREDENTIAL_CHARS } from "./util.ts";

/** Token lifetime from Kling's sample code: `exp = now + 1800`. */
export const KLING_TOKEN_TTL_SECONDS = 1800n;
/** Clock-skew allowance from Kling's sample code: `nbf = now - 5`. */
export const KLING_NOT_BEFORE_SKEW_SECONDS = 5n;

const I64_MAX = 0x7fff_ffff_ffff_ffffn;
const I64_MIN = -0x8000_0000_0000_0000n;
const saturate = (v: bigint) => (v > I64_MAX ? I64_MAX : v < I64_MIN ? I64_MIN : v);
const utf8 = new TextEncoder();

/** `split_credential`: a stored `access_key:secret_key`, both trimmed and non-empty. */
export function splitCredential(credential: string): [string, string] {
  const colon = credential.indexOf(":");
  const refused = () => invalidCredential("expected access_key:secret_key");
  if (colon < 0) throw refused();
  const ak = rustTrim(credential.slice(0, colon));
  const sk = rustTrim(credential.slice(colon + 1));
  if (ak.length === 0 || sk.length === 0 || utf8Length(credential) > MAX_CREDENTIAL_CHARS) throw refused();
  return [ak, sk];
}

/** `kling_token`: the HS256 token Kling expects in `Authorization: Bearer`. `nowUnix` is an i64. */
export function klingToken(credential: string, nowUnix: bigint): string {
  const [ak, sk] = splitCredential(credential);
  const header = base64urlnopad.encode(utf8.encode('{"alg":"HS256","typ":"JWT"}'));
  const claims = toJsonString({
    iss: ak,
    exp: saturate(nowUnix + KLING_TOKEN_TTL_SECONDS),
    nbf: saturate(nowUnix - KLING_NOT_BEFORE_SKEW_SECONDS),
  });
  const signingInput = `${header}.${base64urlnopad.encode(utf8.encode(claims))}`;
  const signature = hmac(sha256, utf8.encode(sk), utf8.encode(signingInput));
  return `${signingInput}.${base64urlnopad.encode(signature)}`;
}
