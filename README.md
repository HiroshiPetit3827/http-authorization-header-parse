# http-authorization-header-parse

Parses an HTTP `Authorization` header into its scheme, parameters, or token68 value.

```js
import { parseAuthorizationHeader } from "http-authorization-header-parse";

// Token-style (Basic, Bearer, ...)
const t = parseAuthorizationHeader("Bearer mF_9.B5f-4.1Zq");
// { scheme: "bearer", params: {}, token: "mF_9.B5f-4.1Zq" }

// Parameter-style (Digest, OAuth, ...)
const p = parseAuthorizationHeader('Digest username="admin", realm="test"');
// { scheme: "digest", params: { username: "admin", realm: "test" }, token: null }
```

## Why this exists

HTTP `Authorization` headers come in two shapes: a scheme followed by a bare token (Basic, Bearer), or a scheme followed by comma-separated `key=value` pairs (Digest, OAuth). Most code only needs to know which shape it is and pull out the relevant bits without pulling in a full HTTP library or hand-writing a parser each time.

The trade-off: this library is intentionally small and uses heuristics rather than an RFC-strict tokenizer. Scheme names are lowercased (they're case-insensitive per RFC 7235). Parameter values inside quoted strings have backslash escapes unescaped per RFC 7230 §3.2.6. Duplicate parameter names use last-write-wins.

## The awkward edge

Classifying a header as token-style versus parameter-style is done by checking whether the value contains an `=` followed by more content. A token68 value that contains an internal `=` (not just trailing base64 padding) will be misclassified as a parameter list and yield empty params. This is a deliberate simplification — token68 with internal `=` is rare, and supporting it fully would require a scheme registry. If you're parsing a scheme you know is token-style, check `result.token` and treat an empty params object as a signal.

This library does not validate that scheme characters are legal `tchar`s per RFC 7230 §3.2.6. It assumes the input came from an HTTP header a server already accepted. Stricter validation would reject some real-world inputs.
