// Display helpers for text that comes from the PC or the data to be signed.

/**
 * Makes control and format characters (escapes, bidi overrides such as
 * U+202E, zero-width characters) visible as \u{...}, so that a user name or
 * namespace cannot hide or reorder what the approval screen shows.
 */
export function visible(s) {
  return String(s).replace(/[\p{Cc}\p{Cf}]/gu, (c) => `\\u{${c.codePointAt(0).toString(16).toUpperCase()}}`);
}
