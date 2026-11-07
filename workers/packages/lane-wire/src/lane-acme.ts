import { z } from "zod";
import { BridgeWireError } from "./error.ts";
import { intSchema, uintSchema } from "./ints.ts";

/**
 * `lane.acme_failed`: a lane VM's report that this boot's certificate order failed (D133), so an operator can read
 * why in the bridge's Workers Logs while the VM's own container log is not public (Phala `public_logs` off).
 *
 * The lane's entrypoint (deploy/tee/bin/entrypoint.mjs) sends one per failed gray-acme run, before it holds and
 * retries, signed with the lane's bridge key like every other bridge call: who it is (the app id the guest agent
 * names, the TLS name, the compose hash when the guest agent gives one), when gray-acme started, how it ended, each
 * CA's one-line reason with the lines gray-acme printed after it (`ca=<host> detail:`: the authorization's and
 * challenge's state and RFC 8555 problem, lego's own lines), and gray-acme's other lines. gray-acme's log carries no
 * key material, token or EAB value (deploy/tee/acme/README.md "Log"), and the entrypoint removes the EAB values and the
 * bridge seed from every line again before it sends one.
 *
 * The bridge verifies the call, refuses more than one report per key within `LANE_ACME_REPORT_INTERVAL_MS`, writes the
 * report as one `lane_acme_failed` log line and keeps nothing else.
 *
 * The target is `lane/<app id>`, so a signature over one app's report never verifies as another's. Every string is one
 * line (no control character) and bounded, so the largest report (`ACME_REPORT_MAX_*`) fits the small-op body bound.
 */

/** The prefix of the target a report signs: `lane/<app id>`. */
export const LANE_REPORT_TARGET_PREFIX = "lane/";
/** At most this many CAs (gray-acme's default list has two). */
export const ACME_REPORT_MAX_CAS = 4;
/** A CA's reason, as gray-acme bounds one log line (deploy/tee/acme/details.go `maxLineBytes`). */
export const ACME_REPORT_MAX_REASON_CHARS = 2048;
/** At most this many detail lines per CA, and of other lines; the entrypoint keeps the first ones. */
export const ACME_REPORT_MAX_LINES = 16;
/** One detail or other line; the entrypoint cuts a longer one. */
export const ACME_REPORT_MAX_LINE_CHARS = 512;
/** The bridge writes at most one report per key within this window (one gray-acme run per 5 minutes, D133). */
export const LANE_ACME_REPORT_INTERVAL_MS = 4 * 60_000;

/** The app id as the guest agent names it: 20 bytes, lower-case hex (D47). */
export const LANE_APP_ID_PATTERN = /^[0-9a-f]{40}$/;
/** gray-acme's TLS_DOMAIN form (deploy/tee/acme/main.go `domainRE`), or empty when the compose sets none. */
const DOMAIN_PATTERN = /^$|^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/;
/** An ACME directory's host as gray-acme names the CA: a DNS name or IP address, with its port if any. */
const CA_HOST_PATTERN = /^[A-Za-z0-9.:[\]-]{1,261}$/;
/** One line: no C0 control character and no DEL. */
const ONE_LINE = /^[^\u0000-\u001f\u007f]+$/;

const line = (max: number) => z.string().min(1).max(max).regex(ONE_LINE, "one line without control characters");

export const laneAcmeCaSchema = z
  .object({
    ca: z.string().regex(CA_HOST_PATTERN, "a CA host"),
    reason: line(ACME_REPORT_MAX_REASON_CHARS),
    details: z.array(line(ACME_REPORT_MAX_LINE_CHARS)).max(ACME_REPORT_MAX_LINES),
  })
  .strict();

export const laneAcmeFailedSchema = z
  .object({
    app_id: z.string().regex(LANE_APP_ID_PATTERN, "20 bytes of lower-case hex"),
    domain: z.string().max(253).regex(DOMAIN_PATTERN, "a lower-case DNS name"),
    compose_hash: z.string().regex(/^[0-9a-f]{64}$/, "a SHA-256 as lower-case hex").nullable(),
    /** When gray-acme started, Unix milliseconds. */
    attempt_ms: uintSchema,
    /** gray-acme's exit code, or null when a signal ended it. */
    exit_code: intSchema.nullable(),
    signal: z.string().regex(/^SIG[A-Z0-9]{1,12}$/, "a signal name").nullable(),
    cas: z.array(laneAcmeCaSchema).max(ACME_REPORT_MAX_CAS),
    /** gray-acme's lines that are not a CA's reason or detail (its progress, the challenge listener's errors). */
    other: z.array(line(ACME_REPORT_MAX_LINE_CHARS)).max(ACME_REPORT_MAX_LINES),
  })
  .strict();
export type LaneAcmeFailedDto = z.infer<typeof laneAcmeFailedSchema>;

/** The answer: the report was written. A second report inside the window is the bridge's `rate_limited` instead. */
export const laneAcmeFailedAnswerSchema = z.object({ logged: z.literal(true) }).strict();
export type LaneAcmeFailedAnswerDto = z.infer<typeof laneAcmeFailedAnswerSchema>;

/** `lane/<app id>`, the target a report signs. */
export function laneReportTarget(appId: string): string {
  if (!LANE_APP_ID_PATTERN.test(appId)) throw new BridgeWireError("invalid_target", null, "an app id is 20 bytes of lower-case hex");
  return `${LANE_REPORT_TARGET_PREFIX}${appId}`;
}
