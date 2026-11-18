/**
 * An upstream credential as control_endpoints stores it and the snapshot carries it: a 12-byte
 * nonce, then the AES-256-GCM ciphertext and tag of the credential's UTF-8, with the endpoint id as
 * additional data, under the 32-byte master key (crates/gray-control/src/lib.rs ControlStore::encrypt
 * and decrypt). The gateway, which holds MASTER_KEY, decrypts with WebCrypto.
 */

/** The master key for `decryptCredential`; 32 bytes. */
export async function importMasterKey(raw: Uint8Array): Promise<CryptoKey> {
  if (raw.byteLength !== 32) throw new RangeError("the master key is 32 bytes");
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["decrypt"]);
}

/** The plaintext credential of `endpointId`, or null when it does not decrypt (the server's Error::Crypto drops the route). */
export async function decryptCredential(key: CryptoKey, endpointId: string, credentialBase64: string): Promise<string | null> {
  let bytes: Uint8Array;
  try {
    bytes = Uint8Array.from(atob(credentialBase64), (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
  if (bytes.byteLength < 12) return null;
  try {
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: bytes.subarray(0, 12), additionalData: new TextEncoder().encode(endpointId) }, key, bytes.subarray(12));
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(plain);
  } catch {
    return null;
  }
}

/**
 * A video job's endpoint as gray-jobs' ConfigDO reads it for the gateway (`videoJobEndpoint`) once the job's route has
 * left the snapshot (crates/gray-control `ControlStore::job_endpoint`; docs/cloudflare-native/media.md 3.2 rule 11):
 * its control_endpoints row as it is now, enabled or not, and its credential sealed as stored (`decryptCredential`
 * opens it), null once the provider removed the key (`active_revoked`, the stored credential cleared) and for a lane
 * relay, whose stored credential is its sentinel, never a key. A rotated-away key is no longer stored: the one read is
 * always the endpoint's current one.
 */
export interface JobEndpointAnswer {
  readonly endpoint: {
    readonly id: string;
    readonly workspace_id: string;
    readonly owner_user_id: string;
    readonly config: string;
    readonly generation: number;
    readonly enabled: number;
  };
  readonly credential: string | null;
}

/** `JobEndpointAnswer`'s read: $1 the endpoint id, $2 its provider workspace; PostgreSQL's base64 breaks its lines. */
export const JOB_ENDPOINT_SQL =
  "SELECT e.id,e.workspace_id,e.owner_user_id,e.config,e.generation,e.enabled," +
  "CASE WHEN COALESCE(l.active_revoked,0)=0 AND octet_length(e.credential)>0 AND ((e.config::jsonb #>> '{auth}') IS DISTINCT FROM 'lane_relay') " +
  "THEN encode(e.credential,'base64') END AS credential " +
  "FROM control_endpoints e LEFT JOIN control_endpoint_lifecycle l ON l.endpoint_id=e.id WHERE e.id=$1 AND e.workspace_id=$2";
