"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
require("../analyzer.js");

const HeaderGuard = globalThis.HeaderGuard;
const SECURE_HTTPS = [
  "HTTP/2 200",
  "strict-transport-security: max-age=31536000; includeSubDomains",
  "content-security-policy: default-src 'self'; script-src 'self' 'nonce-abc'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
  "x-content-type-options: nosniff",
  "referrer-policy: strict-origin-when-cross-origin"
].join("\n");

test("parses status lines and case-insensitive header names", () => {
  const headers = HeaderGuard.parseHeaders("HTTP/2 200\r\nX-Content-Type-Options: nosniff");
  assert.equal(headers["x-content-type-options"], "nosniff");
});

test("the last valid safe Referrer-Policy token is used", () => {
  const headers = HeaderGuard.parseHeaders(
    "Content-Type: text/html\nReferrer-Policy: origin-when-cross-origin, strict-origin-when-cross-origin"
  );
  const report = HeaderGuard.audit(headers, { https: false });
  assert.equal(report.checks.find((check) => check.id === "referrer-policy").status, "pass");
});

test("rejects malformed and empty header input with useful errors", () => {
  assert.throws(() => HeaderGuard.parseHeaders(""), /Paste a response status line/);
  assert.throws(() => HeaderGuard.parseHeaders("HTTP/1.1 200 OK\nnot a header"), /line 2/);
});

test("rejects duplicate security headers rather than guessing their meaning", () => {
  assert.throws(
    () => HeaderGuard.parseHeaders("Content-Security-Policy: default-src 'self'\ncontent-security-policy: script-src 'self'"),
    /more than one Content-Security-Policy/
  );
});

test("secure HTTPS baseline passes required checks", () => {
  const report = HeaderGuard.audit(HeaderGuard.parseHeaders(SECURE_HTTPS), { https: true });
  assert.equal(report.summary.findings, 0);
  assert.equal(report.summary.score, 100);
  assert.ok(report.checks.some((check) => check.id === "clickjacking-protection" && check.status === "pass"));
});

test("HSTS is not incorrectly required for HTTP responses", () => {
  const report = HeaderGuard.audit(
    HeaderGuard.parseHeaders("HTTP/1.1 200 OK\nX-Content-Type-Options: nosniff"),
    { https: false }
  );
  assert.equal(report.checks.find((check) => check.id === "hsts-present").status, "skipped");
  assert.ok(!report.findings.some((finding) => finding.id === "hsts-present"));
});

test("document-only controls are skipped for API responses", () => {
  const report = HeaderGuard.audit(
    HeaderGuard.parseHeaders("HTTP/2 200\nContent-Type: application/json; charset=utf-8"),
    { https: true }
  );
  for (const id of ["csp-present", "clickjacking-protection", "referrer-policy"]) {
    assert.equal(report.checks.find((check) => check.id === id).status, "skipped");
    assert.ok(!report.findings.some((finding) => finding.id === id));
  }
});

test("HTTPS without HSTS is a high-severity finding", () => {
  const report = HeaderGuard.audit(HeaderGuard.parseHeaders("HTTP/2 200\nX-Content-Type-Options: nosniff"), { https: true });
  assert.ok(report.findings.some((finding) => finding.id === "hsts-present" && finding.severity === "high"));
});

test("CSP nonce/hash avoids a false positive for unsafe-inline", () => {
  const headers = HeaderGuard.parseHeaders(
    "Content-Security-Policy: default-src 'self'; script-src 'unsafe-inline' 'nonce-abc'; object-src 'none'; base-uri 'self'"
  );
  const report = HeaderGuard.audit(headers, { https: false });
  assert.ok(!report.findings.some((finding) => finding.id === "csp-unsafe-inline"));
});

test("CSP unsafe-eval is detected and fallback script directives are honored", () => {
  const headers = HeaderGuard.parseHeaders("Content-Security-Policy: default-src 'self' 'unsafe-eval'");
  const report = HeaderGuard.audit(headers, { https: false });
  assert.ok(report.findings.some((finding) => finding.id === "csp-unsafe-eval" && finding.severity === "high"));
});

test("the first duplicate CSP directive is evaluated and wildcard framing is not protection", () => {
  const headers = HeaderGuard.parseHeaders(
    "Content-Security-Policy: script-src 'unsafe-eval'; script-src 'self'; frame-ancestors *"
  );
  const report = HeaderGuard.audit(headers, { https: false });
  assert.ok(report.findings.some((finding) => finding.id === "csp-unsafe-eval"));
  assert.equal(report.checks.find((check) => check.id === "clickjacking-protection").status, "fail");
});

test("CSP frame-ancestors satisfies framing protection without X-Frame-Options", () => {
  const headers = HeaderGuard.parseHeaders("Content-Security-Policy: default-src 'self'; frame-ancestors 'none'");
  const report = HeaderGuard.audit(headers, { https: false });
  assert.equal(report.checks.find((check) => check.id === "clickjacking-protection").status, "pass");
});

test("real response excerpt has no false alarms on five known-safe checks", () => {
  const fixture = fs.readFileSync(
    path.join(__dirname, "fixtures", "github-response.headers.txt"),
    "utf8"
  );
  const report = HeaderGuard.audit(HeaderGuard.parseHeaders(fixture), { https: true });
  const expectedSafeChecks = [
    "hsts-max-age",
    "csp-present",
    "content-type-options",
    "clickjacking-protection",
    "referrer-policy"
  ];
  const falseAlarms = expectedSafeChecks.filter((id) =>
    report.checks.find((check) => check.id === id).status !== "pass"
  );
  assert.deepEqual(falseAlarms, []);
  assert.ok(!report.findings.some((finding) => finding.id === "csp-object-src"));
});

test("emits a stable machine-readable report with actionable checks", () => {
  const report = HeaderGuard.audit(HeaderGuard.parseHeaders(SECURE_HTTPS), { https: true });
  assert.equal(report.schemaVersion, "1.0");
  assert.equal(report.tool, "HeaderGuard");
  assert.ok(Array.isArray(report.findings));
  assert.ok(Array.isArray(report.checks));
  assert.ok(report.checks.every((check) => typeof check.id === "string" && typeof check.status === "string"));
});
