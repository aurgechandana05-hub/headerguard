(function (root) {
  "use strict";

  const SECURITY_HEADERS = new Set([
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy"
  ]);
  const DOCUMENT_MEDIA_TYPES = new Set(["text/html", "application/xhtml+xml", "image/svg+xml"]);
  const REFERRER_POLICIES = new Set([
    "no-referrer",
    "no-referrer-when-downgrade",
    "origin",
    "origin-when-cross-origin",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "unsafe-url"
  ]);
  const SEVERITY_WEIGHT = Object.freeze({
    critical: 30,
    high: 20,
    medium: 10,
    low: 5,
    info: 0
  });
  const SEVERITY_ORDER = Object.freeze({
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4
  });

  function parseHeaders(rawHeaders) {
    if (typeof rawHeaders !== "string" || rawHeaders.trim() === "") {
      throw new Error("Paste a response status line and at least one HTTP header.");
    }

    const headers = Object.create(null);
    let headerCount = 0;

    for (const [index, rawLine] of rawHeaders.split(/\r?\n/).entries()) {
      const line = rawLine.trim();
      if (line === "" || /^HTTP\/\d(?:\.\d)?\s+\d{3}(?:\s|$)/i.test(line)) {
        continue;
      }
      if (line.startsWith("#")) {
        continue;
      }

      const separator = line.indexOf(":");
      if (separator < 1) {
        throw new Error(`Invalid header on line ${index + 1}: expected "Name: value".`);
      }

      const name = line.slice(0, separator).trim();
      const value = line.slice(separator + 1).trim();
      if (!/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(name)) {
        throw new Error(`Invalid header name on line ${index + 1}.`);
      }

      const normalizedName = name.toLowerCase();
      if (headers[normalizedName] !== undefined && SECURITY_HEADERS.has(normalizedName)) {
        throw new Error(
          `The response contains more than one ${name} header; combine or review them before auditing.`
        );
      }
      headers[normalizedName] = headers[normalizedName] === undefined
        ? value
        : `${headers[normalizedName]}, ${value}`;
      headerCount += 1;
    }

    if (headerCount === 0) {
      throw new Error("No HTTP headers were found in the input.");
    }
    return headers;
  }

  function addCheck(checks, check) {
    checks.push(Object.freeze(check));
  }

  function parseCsp(policy) {
    const directives = new Map();
    for (const segment of policy.split(";")) {
      const tokens = segment.trim().split(/\s+/).filter(Boolean);
      const name = tokens[0] && tokens[0].toLowerCase();
      if (name && !directives.has(name)) {
        directives.set(name, tokens.slice(1).map((token) => token.toLowerCase()));
      }
    }
    return directives;
  }

  function isDocumentResponse(headers) {
    const contentType = headers["content-type"];
    if (!contentType) return true;
    const mediaType = contentType.split(";", 1)[0].trim().toLowerCase();
    return DOCUMENT_MEDIA_TYPES.has(mediaType);
  }

  function hasRestrictiveFrameAncestors(directives) {
    const sources = directives.get("frame-ancestors");
    if (!sources || sources.length === 0 || sources.includes("*")) return false;
    return sources.some((source) =>
      source === "'self'" ||
      source === "'none'" ||
      /^[a-z][a-z0-9+.-]*:$/.test(source) ||
      /^(?:(?:https?|wss?):\/\/)?(?:\*\.)?(?:[a-z0-9-]+\.)*[a-z0-9-]+(?::(?:\d+|\*))?(?:\/[^\s]*)?$/.test(source)
    );
  }

  function checkCsp(headers, checks) {
    if (!isDocumentResponse(headers)) {
      addCheck(checks, {
        id: "csp-present",
        title: "Content Security Policy",
        severity: "info",
        status: "skipped",
        message: "The response content type is not an HTML, XHTML, or SVG document.",
        evidence: headers["content-type"],
        recommendation: null
      });
      return;
    }

    const policy = headers["content-security-policy"];
    if (!policy) {
      addCheck(checks, {
        id: "csp-present",
        title: "Content Security Policy",
        severity: "medium",
        status: "fail",
        message: "No Content-Security-Policy header was found.",
        evidence: null,
        recommendation: "Define a policy for the application; start with report-only mode if compatibility is uncertain."
      });
      return;
    }

    addCheck(checks, {
      id: "csp-present",
      title: "Content Security Policy",
      severity: "high",
      status: "pass",
      message: "A Content-Security-Policy header is present.",
      evidence: policy,
      recommendation: null
    });

    const directives = parseCsp(policy);

    const scriptSources = directives.get("script-src") || directives.get("default-src") || [];
    const hasNonceOrHash = scriptSources.some((source) =>
      /^'nonce-[^']+'$/.test(source) || /^'sha(?:256|384|512)-[^']+'$/.test(source)
    );

    if (scriptSources.includes("'unsafe-eval'")) {
      addCheck(checks, {
        id: "csp-unsafe-eval",
        title: "CSP script evaluation",
        severity: "high",
        status: "fail",
        message: "The effective script source allows unsafe-eval.",
        evidence: scriptSources.join(" "),
        recommendation: "Remove 'unsafe-eval' and update the application to avoid evaluating string-based code."
      });
    } else if (scriptSources.includes("'unsafe-inline'") && !hasNonceOrHash) {
      addCheck(checks, {
        id: "csp-unsafe-inline",
        title: "CSP inline scripts",
        severity: "medium",
        status: "warn",
        message: "The effective script source allows inline scripts without a nonce or hash.",
        evidence: scriptSources.join(" "),
        recommendation: "Prefer nonces or hashes; keep this exception only when required and understood."
      });
    }

    if (!directives.has("object-src") && !directives.has("default-src")) {
      addCheck(checks, {
        id: "csp-object-src",
        title: "CSP plugin content",
        severity: "low",
        status: "warn",
        message: "The policy does not explicitly restrict object-based content.",
        evidence: null,
        recommendation: "Consider adding object-src 'none' unless the application requires embedded plugin content."
      });
    }

    if (!directives.has("base-uri")) {
      addCheck(checks, {
        id: "csp-base-uri",
        title: "CSP base URI",
        severity: "low",
        status: "warn",
        message: "The policy does not explicitly restrict document base URLs.",
        evidence: null,
        recommendation: "Consider adding base-uri 'self' or base-uri 'none' when compatible."
      });
    }
  }

  function audit(headers, options) {
    if (!headers || typeof headers !== "object" || Array.isArray(headers)) {
      throw new Error("Headers must be an object returned by parseHeaders().");
    }

    const normalized = Object.create(null);
    for (const [name, value] of Object.entries(headers)) {
      if (typeof value !== "string") {
        throw new Error(`Header "${name}" must have a string value.`);
      }
      normalized[name.toLowerCase()] = value.trim();
    }

    const isHttps = Boolean(options && options.https);
    const checks = [];

    if (isHttps) {
      const hsts = normalized["strict-transport-security"];
      if (!hsts) {
        addCheck(checks, {
          id: "hsts-present",
          title: "HTTPS Strict Transport Security",
          severity: "high",
          status: "fail",
          message: "The HTTPS response does not include Strict-Transport-Security.",
          evidence: null,
          recommendation: "After confirming all subdomains support HTTPS, deploy HSTS with a deliberate max-age."
        });
      } else {
        const maxAge = /(?:^|;)\s*max-age\s*=\s*(\d+)(?:\s*;|$)/i.exec(hsts);
        if (!maxAge) {
          addCheck(checks, {
            id: "hsts-max-age",
            title: "HSTS max-age",
            severity: "high",
            status: "fail",
            message: "Strict-Transport-Security is present but has no valid max-age directive.",
            evidence: hsts,
            recommendation: "Set max-age to an intentional duration; validate HTTPS coverage before enabling includeSubDomains."
          });
        } else if (Number(maxAge[1]) < 15552000) {
          addCheck(checks, {
            id: "hsts-max-age",
            title: "HSTS max-age",
            severity: "medium",
            status: "warn",
            message: "HSTS max-age is shorter than six months.",
            evidence: `max-age=${maxAge[1]}`,
            recommendation: "Consider a longer max-age once HTTPS deployment is stable."
          });
        } else {
          addCheck(checks, {
            id: "hsts-max-age",
            title: "HSTS max-age",
            severity: "high",
            status: "pass",
            message: "HSTS has a max-age of at least six months.",
            evidence: `max-age=${maxAge[1]}`,
            recommendation: null
          });
        }
      }
    } else {
      addCheck(checks, {
        id: "hsts-present",
        title: "HTTPS Strict Transport Security",
        severity: "info",
        status: "skipped",
        message: "HSTS is evaluated only for HTTPS responses.",
        evidence: null,
        recommendation: null
      });
    }

    checkCsp(normalized, checks);

    const contentTypeOptions = normalized["x-content-type-options"];
    addCheck(checks, contentTypeOptions && contentTypeOptions.toLowerCase() === "nosniff"
      ? {
          id: "content-type-options",
          title: "MIME type sniffing protection",
          severity: "medium",
          status: "pass",
          message: "X-Content-Type-Options is set to nosniff.",
          evidence: contentTypeOptions,
          recommendation: null
        }
      : {
          id: "content-type-options",
          title: "MIME type sniffing protection",
          severity: "medium",
          status: "fail",
          message: contentTypeOptions
            ? "X-Content-Type-Options is present but is not set to nosniff."
            : "X-Content-Type-Options is missing.",
          evidence: contentTypeOptions || null,
          recommendation: "Set X-Content-Type-Options: nosniff."
        });

    const csp = normalized["content-security-policy"] || "";
    const cspDirectives = parseCsp(csp);
    const frameAncestors = cspDirectives.get("frame-ancestors") || [];
    const hasFrameAncestors = hasRestrictiveFrameAncestors(cspDirectives);
    const frameOptions = normalized["x-frame-options"];
    const validFrameOptions = frameOptions && /^(deny|sameorigin)$/i.test(frameOptions);
    addCheck(checks, !isDocumentResponse(normalized)
      ? {
          id: "clickjacking-protection",
          title: "Framing protection",
          severity: "info",
          status: "skipped",
          message: "The response content type is not an HTML, XHTML, or SVG document.",
          evidence: normalized["content-type"],
          recommendation: null
        }
      : validFrameOptions || hasFrameAncestors
      ? {
          id: "clickjacking-protection",
          title: "Framing protection",
          severity: "medium",
          status: "pass",
          message: hasFrameAncestors
            ? "CSP defines a frame-ancestors directive."
            : "X-Frame-Options prevents cross-origin framing.",
          evidence: hasFrameAncestors
            ? `frame-ancestors ${frameAncestors.join(" ")}`
            : frameOptions,
          recommendation: null
        }
      : {
          id: "clickjacking-protection",
          title: "Framing protection",
          severity: "medium",
          status: "fail",
          message: "No recognized framing restriction was found.",
          evidence: frameOptions || null,
          recommendation: "Set CSP frame-ancestors to an intentional allowlist, or use X-Frame-Options: DENY/SAMEORIGIN."
        });

    const referrerPolicy = normalized["referrer-policy"];
    const documentResponse = isDocumentResponse(normalized);
    const parsedReferrerPolicies = referrerPolicy
      ? referrerPolicy.split(",").map((value) => value.trim().toLowerCase())
      : [];
    const effectiveReferrerPolicy = parsedReferrerPolicies
      .filter((value) => REFERRER_POLICIES.has(value))
      .at(-1);
    const safeReferrerPolicies = new Set([
      "no-referrer",
      "same-origin",
      "strict-origin",
      "strict-origin-when-cross-origin"
    ]);
    addCheck(checks, !documentResponse
      ? {
          id: "referrer-policy",
          title: "Referrer privacy",
          severity: "info",
          status: "skipped",
          message: "The response content type is not an HTML, XHTML, or SVG document.",
          evidence: normalized["content-type"],
          recommendation: null
        }
      : safeReferrerPolicies.has(effectiveReferrerPolicy)
      ? {
          id: "referrer-policy",
          title: "Referrer privacy",
          severity: "low",
          status: "pass",
          message: "A restrictive Referrer-Policy is configured.",
          evidence: referrerPolicy,
          recommendation: null
        }
      : {
          id: "referrer-policy",
          title: "Referrer privacy",
          severity: referrerPolicy ? "medium" : "low",
          status: "warn",
          message: referrerPolicy
            ? "The Referrer-Policy value is not in the auditor's conservative allowlist."
            : "Referrer-Policy is missing.",
          evidence: referrerPolicy || null,
          recommendation: "Consider strict-origin-when-cross-origin, same-origin, or no-referrer as appropriate."
        });

    const findings = checks.filter((check) => check.status === "fail" || check.status === "warn");
    const deductions = findings.reduce((total, finding) => total + SEVERITY_WEIGHT[finding.severity], 0);
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const finding of findings) {
      counts[finding.severity] += 1;
    }

    return {
      schemaVersion: "1.0",
      tool: "HeaderGuard",
      scannedAt: new Date().toISOString(),
      transport: isHttps ? "https" : "http",
      summary: {
        score: Math.max(0, 100 - deductions),
        passed: checks.filter((check) => check.status === "pass").length,
        findings: findings.length,
        skipped: checks.filter((check) => check.status === "skipped").length,
        bySeverity: counts
      },
      findings,
      checks
    };
  }

  root.HeaderGuard = Object.freeze({
    audit,
    parseHeaders,
    severityOrder: SEVERITY_ORDER
  });
})(typeof globalThis === "undefined" ? this : globalThis);
