import { test } from "node:test";
import assert from "node:assert/strict";
import { parseAuthorizationHeader } from "../src/index.js";

// ─── Empty / null inputs ───────────────────────────────────────────────

test("null input returns empty result", () => {
  assert.deepEqual(parseAuthorizationHeader(null), {
    scheme: null,
    params: {},
    token: null,
  });
});

test("undefined input returns empty result", () => {
  assert.deepEqual(parseAuthorizationHeader(undefined), {
    scheme: null,
    params: {},
    token: null,
  });
});

test("empty string returns empty result", () => {
  assert.deepEqual(parseAuthorizationHeader(""), {
    scheme: null,
    params: {},
    token: null,
  });
});

test("whitespace-only input returns empty result", () => {
  assert.deepEqual(parseAuthorizationHeader("   \t  "), {
    scheme: null,
    params: {},
    token: null,
  });
});

// ─── Token-style schemes (token68) ─────────────────────────────────────

test("Bearer token is parsed", () => {
  const r = parseAuthorizationHeader("Bearer mF_9.B5f-4.1Zq");
  assert.equal(r.scheme, "bearer");
  assert.equal(r.token, "mF_9.B5f-4.1Zq");
  assert.deepEqual(r.params, {});
});

test("Basic base64 token is parsed", () => {
  const r = parseAuthorizationHeader("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
  assert.equal(r.scheme, "basic");
  assert.equal(r.token, "QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
  assert.deepEqual(r.params, {});
});

test("scheme is lowercased", () => {
  const r = parseAuthorizationHeader("BEARER abc123");
  assert.equal(r.scheme, "bearer");
});

test("extra whitespace between scheme and token is tolerated", () => {
  const r = parseAuthorizationHeader("Bearer    abc123");
  assert.equal(r.scheme, "bearer");
  assert.equal(r.token, "abc123");
});

test("trailing whitespace on token is stripped", () => {
  const r = parseAuthorizationHeader("Bearer abc123   ");
  assert.equal(r.token, "abc123");
});

test("scheme with no value has null token", () => {
  const r = parseAuthorizationHeader("Basic");
  assert.equal(r.scheme, "basic");
  assert.equal(r.token, null);
  assert.deepEqual(r.params, {});
});

// ─── Parameter-style schemes ──────────────────────────────────────────

test("single parameter is parsed", () => {
  const r = parseAuthorizationHeader('Digest username="admin"');
  assert.equal(r.scheme, "digest");
  assert.equal(r.token, null);
  assert.deepEqual(r.params, { username: "admin" });
});

test("multiple comma-separated parameters are parsed", () => {
  const r = parseAuthorizationHeader(
    'Digest username="admin", realm="test", nonce="abc123"'
  );
  assert.equal(r.scheme, "digest");
  assert.deepEqual(r.params, {
    username: "admin",
    realm: "test",
    nonce: "abc123",
  });
});

test("parameter names are lowercased", () => {
  const r = parseAuthorizationHeader('Digest USERNAME="admin"');
  assert.deepEqual(r.params, { username: "admin" });
});

test("unquoted parameter values are accepted", () => {
  const r = parseAuthorizationHeader("Digest qop=auth");
  assert.deepEqual(r.params, { qop: "auth" });
});

test("whitespace around parameter name is stripped", () => {
  const r = parseAuthorizationHeader('Digest  username  =  "admin"');
  assert.deepEqual(r.params, { username: "admin" });
});

test("quoted value with escaped quote is unescaped", () => {
  const r = parseAuthorizationHeader('Digest username="a\\"b"');
  assert.equal(r.params.username, 'a"b');
});

test("quoted value with escaped backslash is unescaped", () => {
  const r = parseAuthorizationHeader('Digest username="a\\\\b"');
  assert.equal(r.params.username, "a\\b");
});

test("comma inside quoted value does not split", () => {
  const r = parseAuthorizationHeader('Digest username="a,b", realm="x"');
  assert.deepEqual(r.params, { username: "a,b", realm: "x" });
});

test("duplicate parameter names: last wins", () => {
  const r = parseAuthorizationHeader('Digest qop=auth, qop=auth-int');
  assert.equal(r.params.qop, "auth-int");
});

// ─── Edge cases explicitly chosen ─────────────────────────────────────

test("trailing equals sign is treated as token68 not params", () => {
  // "==" at the end is base64 padding; no key=value pattern, so token.
  const r = parseAuthorizationHeader("Bearer abc==");
  assert.equal(r.token, "abc==");
  assert.deepEqual(r.params, {});
});

// Note: Bearer with internal '=' followed by content is classified as
// params by our heuristic. We don't test it because the README documents
// this as a known limitation, not a supported behaviour.
