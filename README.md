# HeaderGuard

HeaderGuard is a small defensive tool for auditing HTTP response security headers on systems you own or are authorized to assess. It checks response headers only; it does not exploit vulnerabilities, crawl a site, change server configuration, or claim that a site is secure.

## What it checks

- HSTS on HTTPS responses, including whether `max-age` is at least six months. HSTS is deliberately skipped for HTTP.
- Content Security Policy presence, `unsafe-eval`, inline scripts without a nonce/hash, and explicit `object-src` / `base-uri` restrictions.
- `X-Content-Type-Options: nosniff`.
- Framing protection through CSP `frame-ancestors` or `X-Frame-Options: DENY` / `SAMEORIGIN`.
- Referrer-Policy against a conservative allowlist.

Each check has a stable ID, status, severity, evidence, and recommendation. JSON reports use schema version `1.0`. The numeric score is a simple weighted summary, not a compliance rating.
When `Content-Type` identifies a response as JSON, an image, or another non-document resource, document-only CSP, framing, and referrer checks are skipped rather than counted as missing.

## Run the web app

Open `index.html` in a browser, paste a response header block, choose whether it came from HTTPS, and select **Audit response**. The page can also load a built-in example, copy or download the JSON report, and export results without sending the input anywhere.

To capture headers for a host you are authorized to test:

```sh
curl -sS -D response-headers.txt -o /dev/null https://your-owned-host.example
```

Paste the contents of `response-headers.txt` into the app. The analyzer runs in the browser; no server or third-party service is used.
On Windows, use `curl.exe -sS -D response-headers.txt -o NUL https://your-owned-host.example`.

## CLI and CI

Requires Node.js 18 or newer.

```sh
node cli.js --url https://your-owned-host.example --json
node cli.js --input response-headers.txt --https --json --fail-on medium
cat response-headers.txt | node cli.js --input - --https --json
```

On Windows PowerShell, use `Get-Content -Raw response-headers.txt | node cli.js --input - --https --json`.

The URL mode makes one GET request, reads the response headers, cancels the body, and follows standard redirects; it is not a crawler or a port scanner. Use it only for authorized targets. Query strings and fragments are omitted from the reported URL, and local input paths are reduced to their filename. The default CI threshold is `high`; the command exits with status `1` when a finding meets or exceeds the selected `--fail-on` level, status `2` for invalid input or network errors, and `0` otherwise. `--fail-on none` always returns success after a completed audit. JSON goes to stdout, errors go to stderr.

## Validation and false-positive handling

Run the tests with:

```sh
npm test
```

The test suite includes benign HTTPS/HTTP and API-response fixtures and checks known edge cases: HSTS is not required over HTTP, document-only checks are skipped on APIs, CSP `frame-ancestors` counts as framing protection, a `default-src` fallback is understood, and `unsafe-inline` is not flagged when an effective nonce/hash is present. Duplicate security headers are rejected instead of silently selecting one value.

It also tests a sanitized excerpt of one real public HTTPS response in [`test/fixtures/github-response.headers.txt`](test/fixtures/github-response.headers.txt). In this single-sample regression, **0 false alarms were observed across 5 checks independently known to pass** (HSTS, CSP presence, MIME sniffing, framing, and Referrer-Policy). This is a measured real-input sanity check, not a statistically representative false-positive rate. For an assessment, save authorized real response headers, review findings against application behavior, and report the size and labeling method of your corpus before making a broader rate claim.

## What it does not catch

- Missing or insecure headers are signals, not proof of an exploitable vulnerability; a reverse proxy, CDN, route, or application may emit different headers.
- It does not parse all CSP grammar or prove that a policy is compatible, effective, or free of bypasses. It does not audit report-only policies, response bodies, cookies, TLS configuration, CORS, authentication, or application code.
- A present policy may still be dangerously broad. Non-standard or application-specific Referrer-Policy choices may be reported as warnings.
- Header values can vary by path, status code, user agent, and redirect. The CLI audits the final response only.
- It does not make server changes. Verify behavior in staging and follow the service's own operational/change-control process.
