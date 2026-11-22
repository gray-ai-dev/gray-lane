import type { Protocol } from "@gray/protocol";

/**
 * `gray_control::STREAMED_MEDIA_PROTOCOLS`: the APIs of the standard's section 13 that OpenAI's API streams, each
 * asked to stream in its own way (`stream: true` on images and transcriptions, `stream_format: "sse"` on speech).
 * A mapping of one of them may declare that it streams (`ModelMapping.streaming`); no other API has a streamed form.
 */
export const STREAMED_MEDIA_PROTOCOLS: readonly Protocol[] = Object.freeze(["open_ai_image_generations", "open_ai_image_edits", "open_ai_speech", "open_ai_transcriptions"]);

/** `gray_control::streams_media`: whether `protocol` is one of `STREAMED_MEDIA_PROTOCOLS`. */
export function streamsMedia(protocol: Protocol): boolean {
  return STREAMED_MEDIA_PROTOCOLS.includes(protocol);
}
