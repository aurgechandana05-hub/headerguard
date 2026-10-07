#!/usr/bin/env node
"use strict";

const fs = require("node:fs/promises");
const path = require("node:path");
require("./analyzer.js");

const HeaderGuard = globalThis.HeaderGuard;
const SEVERITIES = ["critical", "high", "medium", "low", "none"];

function usage() {
  return [
    "HeaderGuard — defensive HTTP response-header auditor",
    "",
    "Usage:",
    "  node cli.js --url https://your-owned-host.example [--json] [--fail-on high]",
    "  node cli.js --input response-headers.txt [--https] [--json] [--fail-on high]",
    "  type response-headers.txt | node cli.js --input - --https --json",
    "",
    "Options:",
    "  --url URL         Fetch response headers from a host you own or are authorized to test.",
    "  --input PATH      Read a saved HTTP response header block, or '-' for stdin.",
    "  --https           Treat pasted headers as an HTTPS response (required to check HSTS).",
    "  --json            Print the stable machine-readable JSON report.",
    "  --fail-on LEVEL   CI threshold: critical, high (default), medium, low, or none.",
    "  --help            Show this help.",
    "",
    "A threshold fails the command if a finding is at that severity or higher."
  ].join("\n");
}

function parseArgs(args) {
  const options = { failOn: "high", json: false, https: false };
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--help" || arg === "-h") {
      options.help = true;
    } else if (arg === "--json") {
      options.json = true;
    } else if (arg === "--https") {
      options.https = true;
    } else if (arg === "--url" || arg === "--input" || arg === "--fail-on") {
      const value = args[index + 1];
      if (!value || value.startsWith("--")) {
        throw new Error(`${arg} requires a value.`);
      }
      index += 1;
      if (arg === "--url") options.url = value;
      if (arg === "--input") options.input = value;
      if (arg === "--fail-on") options.failOn = value.toLowerCase();
    } else {
      throw new Error(`Unknown option: ${arg}`);
    }
  }

  if (options.help) return options;
  if (Boolean(options.url) === Boolean(options.input)) {
    throw new Error("Provide exactly one of --url or --input.");
  }
  if (!SEVERITIES.includes(options.failOn)) {
    throw new Error(`Invalid --fail-on level. Choose: ${SEVERITIES.join(", ")}.`);
  }
  if (options.url && options.https) {
    throw new Error("--https is only for pasted headers; --url determines the transport.");
  }
  return options;
}

async function readInput(options) {
  if (options.input === "-") {
    return new Promise((resolve, reject) => {
      let text = "";
      process.stdin.setEncoding("utf8");
      process.stdin.on("data", (chunk) => { text += chunk; });
      process.stdin.on("end", () => resolve({ text, https: options.https, source: "stdin" }));
      process.stdin.on("error", reject);
      process.stdin.resume();
    });
  }
  if (options.input) {
    const filePath = path.resolve(options.input);
    const text = await fs.readFile(filePath, "utf8");
    return { text, https: options.https, source: filePath };
  }

  let url;
  try {
    url = new URL(options.url);
  } catch {
    throw new Error("--url must be a valid absolute HTTP or HTTPS URL.");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("--url only supports http:// and https:// URLs.");
  }

  const response = await fetch(url, {
    method: "GET",
    redirect: "follow",
    signal: AbortSignal.timeout(10000),
    headers: { "user-agent": "HeaderGuard/1.0 (defensive security-header audit)" }
  });
  const responseHeaders = [];
  for (const [name, value] of response.headers) {
    responseHeaders.push(`${name}: ${value}`);
  }
  if (response.body) await response.body.cancel();
  const text = [`HTTP/1.1 ${response.status} ${response.statusText}`, ...responseHeaders].join("\n");
  return {
    text,
    https: new URL(response.url).protocol === "https:",
    source: response.url,
    httpStatus: response.status
  };
}

function safeSource(source) {
  try {
    const url = new URL(source);
    return `${url.protocol}//${url.host}${url.pathname}`;
  } catch {
    return source === "stdin" ? source : path.basename(source);
  }
}

function shouldFail(report, threshold) {
  if (threshold === "none") return false;
  const maxSeverity = HeaderGuard.severityOrder[threshold];
  return report.findings.some((finding) => HeaderGuard.severityOrder[finding.severity] <= maxSeverity);
}

function humanReport(report, source) {
  const lines = [
    `HeaderGuard audit: ${source}`,
    `Score: ${report.summary.score}/100 | ${report.summary.findings} finding(s) | ${report.summary.passed} check(s) passed`
  ];
  if (report.findings.length === 0) {
    lines.push("No findings.");
  } else {
    for (const finding of [...report.findings].sort((a, b) =>
      HeaderGuard.severityOrder[a.severity] - HeaderGuard.severityOrder[b.severity]
    )) {
      lines.push(`- ${finding.severity.toUpperCase()} ${finding.title}: ${finding.message}`);
      if (finding.recommendation) lines.push(`  Recommendation: ${finding.recommendation}`);
    }
  }
  return lines.join("\n");
}

async function main() {
  let options;
  try {
    options = parseArgs(process.argv.slice(2));
    if (options.help) {
      process.stdout.write(`${usage()}\n`);
      return;
    }

    const input = await readInput(options);
    const headers = HeaderGuard.parseHeaders(input.text);
    const report = HeaderGuard.audit(headers, { https: input.https });
    report.source = safeSource(input.source);
    if (input.httpStatus !== undefined) report.httpStatus = input.httpStatus;

    process.stdout.write(options.json
      ? `${JSON.stringify(report, null, 2)}\n`
      : `${humanReport(report, report.source)}\n`);
    if (shouldFail(report, options.failOn)) process.exitCode = 1;
  } catch (error) {
    process.stderr.write(`HeaderGuard: ${error.message}\n`);
    process.exitCode = 2;
  }
}

main();
