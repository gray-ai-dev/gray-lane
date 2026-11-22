import {
  VIDEO_DUE_MAX_JOBS,
  VIDEO_DUE_TARGET,
  bridgeCall,
  videoDueRequestDtoOf,
  videoGetRequestDtoOf,
  videoJobOf,
  videoJobTarget,
  videoPutRequestDtoOf,
  videoUpdateRequestDtoOf,
  type LaneVideoJob,
  type LaneVideoJobChange,
  type LaneVideoJobCreate,
  type VideoLeaseAction,
  type VideoPutOutcome,
  type VideoUpdateOutcome,
} from "@gray/lane-wire";
import { BridgeClient, type BridgeClientOptions } from "./client.ts";

/**
 * The entry's video job store (the bridge ops `video.put`, `video.get`, `video.update` and `video.due`, @gray/lane-wire
 * video-jobs.ts; docs/design/standard-media-at-entry.md section 2.7): one record per job behind the bridge, so that any
 * entry replica can follow, poll and settle a job another replica created.
 *
 * Every document is built by the wire package's own converters, which check it against the store's strict schema
 * before it is sent: a record holds ids, closed words, counts, times, the hold token, the frozen evidence and the
 * ledger columns, and a member that could hold a prompt, a `metadata` value or a URL does not pass. A call that fails
 * (no answer, a timeout, a status that is not 2xx, a document off the schema) throws, as every bridge call does
 * (client.ts): the caller decides whether to retry.
 */
export interface LaneVideoStore {
  /** Writes the create's record, due its first background poll at `nextPollAtMs`: `created`, `same` (this create again) or `conflict` (another job under the id). */
  put(job: LaneVideoJobCreate, nextPollAtMs: number, timeoutMs?: number): Promise<{ readonly outcome: VideoPutOutcome; readonly job: LaneVideoJob }>;
  /** The record of `id`, or null. */
  get(id: string, timeoutMs?: number): Promise<LaneVideoJob | null>;
  /** One change decided on `version` by `replica`, with what it does to the job's lease; `nextPollAtMs` reschedules its background poll. */
  update(input: VideoUpdate, timeoutMs?: number): Promise<{ readonly outcome: VideoUpdateOutcome; readonly job: LaneVideoJob | null }>;
  /** Up to `limit` jobs whose poll is due, leased to `replica`. */
  due(replica: number, limit?: number, timeoutMs?: number): Promise<LaneVideoJob[]>;
}

export interface VideoUpdate {
  readonly id: string;
  readonly version: number;
  readonly replica: number;
  readonly lease: VideoLeaseAction;
  readonly change: LaneVideoJobChange;
  readonly nextPollAtMs: number | null;
}

/** `LaneVideoStore` over the bridge, signed with the lane's bridge key. */
export class RemoteVideoStore extends BridgeClient implements LaneVideoStore {
  constructor(options: BridgeClientOptions) {
    super(options);
  }

  async put(job: LaneVideoJobCreate, nextPollAtMs: number, timeoutMs?: number): Promise<{ readonly outcome: VideoPutOutcome; readonly job: LaneVideoJob }> {
    const answer = await this.call("video.put", bridgeCall("video.put", videoJobTarget(job.id)), videoPutRequestDtoOf(job, nextPollAtMs), timeoutMs === undefined ? {} : { timeoutMs });
    return { outcome: answer.outcome, job: videoJobOf(answer.job) };
  }

  async get(id: string, timeoutMs?: number): Promise<LaneVideoJob | null> {
    const answer = await this.call("video.get", bridgeCall("video.get", videoJobTarget(id)), videoGetRequestDtoOf(id), timeoutMs === undefined ? {} : { timeoutMs });
    return answer.job === null ? null : videoJobOf(answer.job);
  }

  async update(input: VideoUpdate, timeoutMs?: number): Promise<{ readonly outcome: VideoUpdateOutcome; readonly job: LaneVideoJob | null }> {
    const answer = await this.call("video.update", bridgeCall("video.update", videoJobTarget(input.id)), videoUpdateRequestDtoOf(input), timeoutMs === undefined ? {} : { timeoutMs });
    return { outcome: answer.outcome, job: answer.job === null ? null : videoJobOf(answer.job) };
  }

  async due(replica: number, limit: number = VIDEO_DUE_MAX_JOBS, timeoutMs?: number): Promise<LaneVideoJob[]> {
    const answer = await this.call("video.due", bridgeCall("video.due", VIDEO_DUE_TARGET), videoDueRequestDtoOf(replica, limit), timeoutMs === undefined ? {} : { timeoutMs });
    return answer.jobs.map(videoJobOf);
  }
}

/** The entry's video job store over the bridge. */
export function remoteVideoStore(options: BridgeClientOptions): LaneVideoStore {
  return new RemoteVideoStore(options);
}
