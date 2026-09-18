// ─────────────────────────────────────────────────────────────────────────────
// SHARED UTILITIES – Input sanitization & validation helpers
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Sanitize user input for use in URLs and OS commands.
 * Strips control characters, null bytes, path traversal, and common injection patterns.
 */
export function sanitizeInput(raw) {
  if (typeof raw !== 'string') return '';
  return raw
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')  // Control chars
    .replace(/\.\.\//g, '')                                 // Path traversal
    .replace(/[<>|&;`$]/g, '')                              // Shell metacharacters
    .trim();
}

/**
 * Detect if a string looks like a phone number
 */
export function isPhoneLike(str) {
  const cleaned = str.replace(/[\s\-()]/g, '');
  return /^(\+|08|62|\d{7,15}$)/.test(cleaned);
}

/**
 * Mask sensitive data in a string (for logging)
 */
export function maskSensitive(str) {
  if (!str || str.length <= 10) return str;
  const prefix = str.slice(0, 5);
  const suffix = str.slice(-3);
  return `${prefix}${'•'.repeat(Math.min(str.length - 8, 20))}${suffix}`;
}

/**
 * Generate a timestamped filename slug
 */
export function timestampSlug() {
  return new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
}
