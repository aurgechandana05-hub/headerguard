"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const path = require("node:path");

const cliPath = path.resolve(__dirname, "../cli.js");

function runCli(input, ...args) {
  return spawnSync(process.execPath, [cliPath, "--input", "-", ...args], {
    input,
    encoding: "utf8"
  });
}

test("CLI writes JSON to stdout and returns success below the selected threshold", () => {
  const headers = [
    "HTTP/2 200",
    "Strict-Transport-Security: max-age=31536000",
    "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options: nosniff",
    "Referrer-Policy: no-referrer"
  ].join("\n");
  const result = runCli(headers, "--https", "--json", "--fail-on", "high");
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).schemaVersion, "1.0");
});

test("CLI exits nonzero when a finding meets the CI threshold", () => {
  const result = runCli(
    "HTTP/2 200\nContent-Type: text/html",
    "--https",
    "--json",
    "--fail-on",
    "high"
  );
  assert.equal(result.status, 1);
  assert.ok(JSON.parse(result.stdout).findings.some((finding) => finding.id === "hsts-present"));
});

test("CLI reports invalid input on stderr with a distinct error status", () => {
  const result = runCli("not a header", "--json");
  assert.equal(result.status, 2);
  assert.match(result.stderr, /Invalid header on line 1/);
  assert.equal(result.stdout, "");
});
