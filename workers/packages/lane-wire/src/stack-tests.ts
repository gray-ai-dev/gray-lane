import { OPENAI_COMPATIBLE_VENDOR_IDS, type LaneStackVendor } from "@gray/lane";
import { z } from "zod";
import { BridgeWireError } from "./error.ts";
import { integersOfJson, numbersOfJson, uintSchema } from "./ints.ts";
import { STACK_ATTEMPT_CLASSES, STACK_TEST_CODES, STACK_TEST_OUTCOMES, STACK_TEST_PROTOCOLS, STACK_TEST_SCHEDULE_MODES, STACK_VENDOR_CODES, type StackAttemptClass, type StackTestCode, type StackVendorCode } from "./stack-health.ts";
import { stackWindowsSchema, type StackReportWindow } from "./stack-report.ts";
import { STACK_WIRE_ID_PATTERN } from "./stack-rules.ts";

/**
 * `stack.tests` (docs/confidential-lane-supply-implementation.md S44): one-click account tests. The panel queues a test
 * (`POST …/accounts/{a}/tests`), the console creates scheduled ones when the VM polls (`test_schedule`); the entry sends
 * the results of the tests it ran and gets the tests still pending. Egress makes each test's request from its vendor
 * operations table (deploy/tee/egress/vendor-ops-v1.json), so no text of the relay's goes with one. A pending test the VM
 * has not answered within LANE_STACK_TEST_EXPIRY_MS (120 s by default, at least 65 s) of being queued expires: it is no
 * longer pending, and a result sent for it later is dropped, as for proxy checks.
 *
 * A result carries what egress measured and classified (S44's answer) and the entry's clock when it ended
 * (`checked_ms`); nothing of the vendor's answer but SSE event types was read, and nothing of it is kept. Its windows
 * are the report's (minutes). A test is outside receipts and money: no rid, feed, request record or charge.
 */

/** The most results one call carries and the most tests pending per relay (`PROXY_CHECK_RESULTS_MAX`, S44). */
export const STACK_TESTS_MAX = 64;
/** The model a test names: egress inserts at most 256 bytes of it into its template (S44). */
export const STACK_TEST_MODEL_MAX = 256;

/**
 * The protocols a test of each vendor may speak (egress's `stackProtocolRoutes`, S16): the first is the default. An
 * OpenAI-compatible vendor speaks Chat only.
 */
export const STACK_TEST_PROTOCOLS_OF: Readonly<Record<LaneStackVendor, readonly (typeof STACK_TEST_PROTOCOLS)[number][]>> = Object.freeze({
  anthropic: ["anthropic_messages"],
  openai: ["open_ai_responses", "open_ai_chat"],
  chatgpt_codex: ["open_ai_responses"],
  ...(Object.fromEntries(OPENAI_COMPATIBLE_VENDOR_IDS.map((id) => [id, ["open_ai_chat"]])) as unknown as Record<(typeof OPENAI_COMPATIBLE_VENDOR_IDS)[number], readonly ["open_ai_chat"]>),
});

const id = z.string().regex(STACK_WIRE_ID_PATTERN);
const testId = z.string().regex(/^[0-9a-f]{32}$/);

/**
 * The relay's test schedule (S44): which accounts the console tests on its own, how often. Off by default, with every
 * 60 minutes as the starting interval (workers/db migration 0047); 10 minutes is the shortest allowed.
 */
export const stackTestScheduleSchema = z.object({ mode: z.enum(STACK_TEST_SCHEDULE_MODES), every_minutes: z.number().int().min(10).max(1440) }).strict();
export type StackTestSchedule = z.infer<typeof stackTestScheduleSchema>;
export const STACK_TEST_SCHEDULE_DEFAULT: StackTestSchedule = Object.freeze({ mode: "off", every_minutes: 60 });

const resultSchema = z
  .object({
    test_id: testId,
    outcome: z.enum(STACK_TEST_OUTCOMES),
    code: z.enum(STACK_TEST_CODES).nullable(),
    status: uintSchema.min(100n).max(599n).nullable(),
    class: z.enum(STACK_ATTEMPT_CLASSES).nullable(),
    vendor_code: z.enum(STACK_VENDOR_CODES).nullable(),
    first_byte_ms: uintSchema.nullable(),
    first_token_ms: uintSchema.nullable(),
    total_ms: uintSchema.nullable(),
    windows: stackWindowsSchema,
    cleared: uintSchema.max(4_294_967_295n),
    checked_ms: uintSchema,
  })
  .strict()
  .refine((r) => (r.outcome === "ok") === (r.code === null), { message: "an ok test has no code, a failed one names one", path: ["code"] });

export const stackTestsRequestSchema = z.object({ relay_id: id, results: z.array(resultSchema).max(STACK_TESTS_MAX) }).strict();
export type StackTestsRequestDto = z.infer<typeof stackTestsRequestSchema>;

const pendingSchema = z.object({ test_id: testId, account_id: id, model: z.string().min(1).max(STACK_TEST_MODEL_MAX), protocol: z.enum(STACK_TEST_PROTOCOLS) }).strict();

export const stackTestsAnswerSchema = z.object({ pending: z.array(pendingSchema).max(STACK_TESTS_MAX) }).strict();
export type StackTestsAnswerDto = z.infer<typeof stackTestsAnswerSchema>;

/** One result as the console records it: the wire result with JS numbers. */
export interface StackTestResult {
  readonly test_id: string;
  readonly outcome: "ok" | "failed";
  readonly code: StackTestCode | null;
  readonly status: number | null;
  readonly class: StackAttemptClass | null;
  readonly vendor_code: StackVendorCode | null;
  readonly first_byte_ms: number | null;
  readonly first_token_ms: number | null;
  readonly total_ms: number | null;
  readonly windows: readonly StackReportWindow[];
  readonly cleared: number;
  readonly checked_ms: number;
}
/** One test the entry is to run. */
export interface PendingStackTest {
  readonly test_id: string;
  readonly account_id: string;
  readonly model: string;
  readonly protocol: (typeof STACK_TEST_PROTOCOLS)[number];
}
export interface StackTestsAnswer {
  readonly pending: readonly PendingStackTest[];
}

/** The results a call carries, with JS numbers (the console's input). */
export function stackTestResultsOf(dto: StackTestsRequestDto): StackTestResult[] {
  return numbersOfJson(dto.results, "results") as StackTestResult[];
}

/** The results with JS numbers checked again by the wire's schema (the console's own guard on what the bridge hands it). */
export function checkedStackTestResults(results: unknown): StackTestResult[] {
  const parsed = z.array(resultSchema).max(STACK_TESTS_MAX).safeParse(integersOfJson(results, "results"));
  if (!parsed.success) throw new BridgeWireError("invalid_document", parsed.error.issues[0]?.path.map(String).join(".") ?? null, "the test results are not their wire shape");
  return numbersOfJson(parsed.data, "results") as StackTestResult[];
}

/** The wire answer of the console's answer (a malformed one throws). */
export function stackTestsAnswerDtoOf(answer: StackTestsAnswer): StackTestsAnswerDto {
  const parsed = stackTestsAnswerSchema.safeParse(integersOfJson(answer, ""));
  if (!parsed.success) throw new BridgeWireError("invalid_document", parsed.error.issues[0]?.path.map(String).join(".") ?? null, "the pending tests are not their wire shape");
  return parsed.data;
}
