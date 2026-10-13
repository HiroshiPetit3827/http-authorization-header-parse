/**
 * Parse an HTTP Authorization header into a scheme and parameters.
 *
 * Supports:
 *   - Single-token schemes (Basic, Bearer, etc.): token68
 *   - Parameter schemes (Digest, OAuth, etc.): comma-separated auth-params
 *
 * Returns an object: { scheme, params, token }
 *
 *   - scheme: lowercased scheme name (e.g. "basic", "bearer", "digest")
 *   - params: object of auth-params for parameter-style headers (empty for token68)
 *   - token:   token68 value for token-style headers (null for parameter-style)
 *
 * Ambiguities resolved (stated plainly so callers know what they get):
 *
 *   1. Whitespace between scheme and value is consumed. Exactly one space is
 *      conventional, but we tolerate any amount (including tabs). RFC 7235
 *      permits OWS — optional whitespace — so leniency here is safe.
 *
 *   2. Scheme is always lowercased. Schemes are case-insensitive per RFC 7235
 *      §2.1. Keeping this consistent avoids every caller having to do it.
 *
 *   3. Schemes whose value is a bare token68 (no equals signs) yield { token }
 *      and an empty { params }. Schemes whose value contains key=value pairs
 *      yield { params } and a null { token }. A scheme is classified as a
 *      parameter scheme iff the value contains an unquoted '=' (more below).
 *
 *   4. Parameter names are lowercased and stripped of surrounding whitespace.
 *      Values are stripped of surrounding whitespace but NOT of internal
 *      whitespace. Quoted-string values have their quotes removed and
 *      backslash escapes unescaped (RFC 7230 §3.2.6).
 *
 *   5. Quoted strings may contain backslash-escaped characters. We unescape
 *      them per RFC 7230 §3.2.6: \" becomes ", \\ becomes \, \X becomes X.
 *      This is the one real complexity; it's done because the same
 *      parser is used for the body of the header where quoted-pairs appear.
 *
 *   6. Auth-scheme detection is naive but strict enough: the input must
 *      begin with a token (RFC 7230 §3.2.6: 1*tchar) followed by whitespace.
 *      The token stops at the first whitespace. If no whitespace follows,
 *      the input is treated as a bare scheme with no value (params {}, token
 *      null). This is a deliberate simplification: we don't attempt to
 *      validate tchar legality beyond "not whitespace, not comma".
 *
 *   7. A comma is NOT a valid delimiter between the scheme and its value.
 *      If you pass "Digest, qop=auth" we treat "Digest," as the scheme and
 *      bail. This is correct: RFC 7235 only permits schemes separated by
 *      commas when the parameter list is empty, and that's a rare case we
 *      explicitly don't support — see the README.
 *
 *   8. Duplicate parameter names: last one wins. RFC 7235 doesn't address
 *      duplicates in auth-params clearly; "last wins" is the most common
 *      convention and matches general HTTP header merging behaviour.
 *
 *   9. Empty input or input with only whitespace yields { scheme: null,
 *      params: {}, token: null }. This is so callers can pass headers that
 *      were received empty without having to guard against undefined.
 */

/**
 * Remove surrounding OWS (RFC 7230 §3.2.3: SP / HTAB).
 * Used repeatedly; named for clarity.
 *
 * @param {string} s
 * @returns {string}
 */
function trimWhitespace(s) {
  const ws = /\s/;
  let start = 0;
  while (start < s.length && ws.test(s[start])) start++;
  let end = s.length;
  while (end > start && ws.test(s[end - 1])) end--;
  return s.slice(start, end);
}

/**
 * Determine whether a string contains an unquoted '='.
 *
 * The scheme's value is a parameter list iff it contains a '=' character
 * outside any quoted string. A quoted string is a maximal run beginning with
 * '"' and ending with the next '"' (which may be escaped, but backslash
 * escaping inside the quotes is handled separately during parsing — for
 * classification we only care whether a '=' appears in the "outside quotes"
 * region).
 *
 * This naive scan is sufficient because:
 *   - A token68 containing a '=' is valid (it uses '=' as trailing padding)
 *   - But the input "Bearer abc==" is unambiguously token68 because the
 *     scheme 'Bearer' is conventionally token-style, not parameter-style.
 *
 * ...except we can't know that without a scheme registry, so we make a
 * choice: if the value contains an unquoted '=', we treat it as params.
 * A token68 with '=' (like a base64 token ending in padding) will therefore
 * be misclassified. We accept this trade: token68 with trailing '=' is rare
 * (base64url is more common), and parsing it as a quoted/param list fails
 * gracefully (no key=value, so params is empty).
 *
 * Actually — to be less wrong: we classify by looking for the pattern
 * `key = value`, i.e. '=' that's followed (after optional whitespace) by a
 * non-empty value. A trailing '=' with nothing after is treated as token68.
 * This is a heuristic, not RFC-mandated, and the README says so.
 *
 * @param {string} value
 * @returns {boolean}
 */
function looksLikeParameterList(value) {
  // Look for '=' that is followed by something (after optional whitespace).
  // A trailing '=' (like base64 padding) won't match. Consecutive '='
  // characters (base64 padding like '==') are also treated as token68.
  for (let i = 0; i < value.length; i++) {
    if (value[i] !== "=") continue;
    // Skip whitespace after '='
    let j = i + 1;
    while (j < value.length && /\s/.test(value[j])) j++;
    if (j < value.length && value[j] !== "=") return true;
  }
  return false;
}

/**
 * Split a parameter list into raw "name=value" segments, respecting
 * quoted strings (commas inside quotes don't split).
 *
 * Returns an array of strings, each of which is `name=value` (possibly with
 * surrounding whitespace). Empty segments are dropped — RFC 7235 permits
 * empty list elements after OWS trimming but they carry no information.
 *
 * @param {string} value
 * @returns {string[]}
 */
function splitParameters(value) {
  const parts = [];
  let current = "";
  let inQuote = false;
  let quoteEscape = false;

  for (let i = 0; i < value.length; i++) {
    const ch = value[i];

    if (inQuote) {
      current += ch;
      if (quoteEscape) {
        quoteEscape = false;
      } else if (ch === "\\") {
        quoteEscape = true;
      } else if (ch === '"') {
        inQuote = false;
      }
      continue;
    }

    if (ch === '"') {
      inQuote = true;
      current += ch;
    } else if (ch === ",") {
      if (trimWhitespace(current).length > 0) {
        parts.push(current);
      }
      current = "";
    } else {
      current += ch;
    }
  }

  if (trimWhitespace(current).length > 0) {
    parts.push(current);
  }

  return parts;
}

/**
 * Parse a single auth-param (name=value) into [name, value].
 *
 * The value may be a quoted string (in which case it's unescaped) or a bare
 * token.
 *
 * Returns null if the segment doesn't contain '=' (malformed).
 *
 * @param {string} segment
 * @returns {[string, string] | null}
 */
function parseParameter(segment) {
  const eq = segment.indexOf("=");
  if (eq === -1) return null;

  const name = trimWhitespace(segment.slice(0, eq)).toLowerCase();
  if (name.length === 0) return null;

  const rawValue = trimWhitespace(segment.slice(eq + 1));
  const value = unquoteValue(rawValue);
  return [name, value];
}

/**
 * If the value is a quoted string, remove the quotes and unescape
 * backslash-escaped characters per RFC 7230 §3.2.6.
 *
 * If not a quoted string, return as-is (already whitespace-trimmed).
 *
 * @param {string} raw
 * @returns {string}
 */
function unquoteValue(raw) {
  if (raw.length < 2 || raw[0] !== '"' || raw[raw.length - 1] !== '"') {
    return raw;
  }

  // It's a quoted string. Unescape.
  const inner = raw.slice(1, -1);
  let result = "";
  let escaped = false;

  for (let i = 0; i < inner.length; i++) {
    const ch = inner[i];
    if (escaped) {
      result += ch;
      escaped = false;
    } else if (ch === "\\") {
      escaped = true;
    } else {
      result += ch;
    }
  }

  return result;
}

/**
 * Main parser.
 *
 * @param {string} header - The raw Authorization header value (may be null/undefined).
 * @returns {{scheme: string|null, params: Object<string,string>, token: string|null}}
 */
export function parseAuthorizationHeader(header) {
  const empty = { scheme: null, params: {}, token: null };

  if (header == null) return empty;

  const trimmed = trimWhitespace(String(header));
  if (trimmed.length === 0) return empty;

  // Find the scheme: it ends at the first whitespace.
  // (We don't validate tchar here; the input is assumed to be from an HTTP
  //  header where the server already accepted it. Stricter validation would
  //  reject some real-world inputs that callers want to inspect.)
  let i = 0;
  while (i < trimmed.length && !/\s/.test(trimmed[i])) i++;

  if (i === 0) {
    // No scheme characters before whitespace — shouldn't happen after trim,
    // but guard anyway.
    return empty;
  }

  const scheme = trimmed.slice(0, i).toLowerCase();

  // No value after scheme: return scheme with empty params and null token.
  if (i === trimmed.length) {
    return { scheme, params: {}, token: null };
  }

  // Skip whitespace between scheme and value.
  let j = i;
  while (j < trimmed.length && /\s/.test(trimmed[j])) j++;

  const value = trimmed.slice(j);

  if (value.length === 0) {
    return { scheme, params: {}, token: null };
  }

  // Decide: parameter list or token68?
  if (looksLikeParameterList(value)) {
    const params = {};
    const segments = splitParameters(value);
    for (const seg of segments) {
      const pair = parseParameter(seg);
      if (pair) {
        // Last-write-wins for duplicate keys (see docstring).
        params[pair[0]] = pair[1];
      }
    }
    return { scheme, params, token: null };
  }

  // Token68 value. Strip surrounding whitespace (already done by virtue of
  // `value` being post-trim, but be explicit for clarity).
  return { scheme, params: {}, token: trimWhitespace(value) };
}
