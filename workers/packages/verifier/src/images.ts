/**
 * The colors a check names and the solid 32x32 PNG of each (native.rs `Color`): a vision check attaches one
 * of VISION_COLORS and asks its color; an image output check asks for one of IMAGE_OUTPUT_COLORS. A module of
 * its own, with no imports, so that a stand-in supplier can tell the images apart without loading the
 * verifier (workers/staging/upstream).
 */

/**
 * `Color::VISION`: the colors a vision check's image may show. A model that does not see the image and names
 * one of them anyway names the right one on one draw in six, and a wrong one fails the check at once
 * (`image_misread`).
 */
export const VISION_COLORS = ["red", "green", "blue", "yellow", "black", "white"] as const;
export type Color = (typeof VISION_COLORS)[number];

/** `Color::IMAGE_OUTPUT`: the colors an image output check asks for, those of one RGB channel each. */
export const IMAGE_OUTPUT_COLORS = ["red", "green", "blue"] as const satisfies readonly Color[];

/** Base64 of each vision color's image, in VISION_COLORS order (`Color::png`). */
export const PROBE_IMAGES = [
  "iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAIAAAD8GO2jAAAAKElEQVR4nO3NsQ0AAAzCMP5/un0CNkuZ41wybXsHAAAAAAAAAAAAxR4yw/wuPL6QkAAAAABJRU5ErkJggg==",
  "iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAIAAAD8GO2jAAAAJklEQVR4nO3NsQkAAAjAsP7/tF7hIASyp6ZbAoFAIBAIBAKB4EuwNof8LkGrxSIAAAAASUVORK5CYII=",
  "iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAIAAAD8GO2jAAAAJklEQVR4nO3NsQkAAAjAsP7/tF7hIASyp5pjAoFAIBAIBAKB4EmwOkv8Lm7+zY4AAAAASUVORK5CYII=",
  "iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAIAAAD8GO2jAAAAKElEQVR4nO3NsQ0AAAzCMP5/mj5RNkuZ47SZtr0DAAAAAAAAAACAxw5dKvhqiYlpRgAAAABJRU5ErkJggg==",
  "iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAIAAAD8GO2jAAAAGUlEQVR4nO3BMQEAAADCoPVP7WENoAAAAG4MIAABt9NlCQAAAABJRU5ErkJggg==",
  "iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAIAAAD8GO2jAAAAJklEQVR4nO3NMQ0AAAwDoPo33arYsQQMkB6LQCAQCAQCgUAg+BIMi1X0pjxKe0gAAAAASUVORK5CYII=",
] as const;

/** The order number every check's answer must carry (native.rs `order_number`): `4817-2093-5561`. */
export const ORDER_NUMBER = /\b\d{4}-\d{4}-\d{4}\b/;
