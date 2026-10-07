(function () {
  "use strict";

  const form = document.getElementById("audit-form");
  const headersInput = document.getElementById("headers-input");
  const httpsToggle = document.getElementById("https-toggle");
  const results = document.getElementById("results");
  const errorMessage = document.getElementById("error-message");
  const checksList = document.getElementById("checks-list");
  const jsonOutput = document.getElementById("json-output");
  let currentReport = null;

  const EXAMPLE = [
    "HTTP/2 200",
    "content-type: text/html; charset=utf-8",
    "strict-transport-security: max-age=31536000; includeSubDomains",
    "content-security-policy: default-src 'self'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
    "x-content-type-options: nosniff",
    "referrer-policy: strict-origin-when-cross-origin"
  ].join("\n");

  function makeText(tag, className, text) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    element.textContent = text;
    return element;
  }

  function renderCheck(check) {
    const row = document.createElement("article");
    row.className = `check-row ${check.status}`;

    const icon = makeText("span", "check-mark",
      check.status === "pass" ? "✓" : check.status === "skipped" ? "–" : "!");
    icon.setAttribute("aria-hidden", "true");
    const content = document.createElement("div");
    content.className = "check-content";
    content.append(makeText("strong", "", check.title));
    content.append(makeText("p", "", check.message));
    if (check.evidence) content.append(makeText("span", "evidence", check.evidence));
    if (check.recommendation && check.status !== "pass" && check.status !== "skipped") {
      content.append(makeText("p", "recommendation", `Suggestion: ${check.recommendation}`));
    }
    const badgeLabel = check.status === "pass" ? "pass" : check.status === "skipped" ? "skipped" : check.severity;
    const badgeClass = check.status === "pass"
      ? "passed"
      : check.status === "skipped"
        ? "skipped-label"
        : check.severity;
    const severity = makeText("span", `severity ${badgeClass}`, badgeLabel);
    row.append(icon, content, severity);
    return row;
  }

  function displayReport(report) {
    currentReport = report;
    document.getElementById("score-value").textContent = String(report.summary.score);
    document.querySelector(".score-orbit").style.setProperty("--score-angle", `${report.summary.score * 3.6}deg`);
    document.getElementById("passed-count").textContent = String(report.summary.passed);
    document.getElementById("finding-count").textContent = String(report.summary.findings);
    const transport = document.getElementById("transport-badge");
    transport.textContent = report.transport;
    transport.classList.toggle("http", report.transport === "http");

    checksList.replaceChildren(...report.checks.map(renderCheck));
    jsonOutput.textContent = JSON.stringify(report, null, 2);
    errorMessage.hidden = true;
    results.hidden = false;
    results.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    try {
      const headers = window.HeaderGuard.parseHeaders(headersInput.value);
      const report = window.HeaderGuard.audit(headers, { https: httpsToggle.checked });
      displayReport(report);
    } catch (error) {
      errorMessage.textContent = error.message;
      errorMessage.hidden = false;
      results.hidden = true;
      headersInput.focus();
    }
  });

  document.getElementById("load-example").addEventListener("click", () => {
    headersInput.value = EXAMPLE;
    httpsToggle.checked = true;
    headersInput.focus();
  });

  document.getElementById("clear-input").addEventListener("click", () => {
    headersInput.value = "";
    results.hidden = true;
    errorMessage.hidden = true;
    currentReport = null;
    headersInput.focus();
  });

  document.getElementById("copy-report").addEventListener("click", async (event) => {
    if (!currentReport) return;
    const button = event.currentTarget;
    try {
      await navigator.clipboard.writeText(JSON.stringify(currentReport, null, 2));
      button.innerHTML = "<span aria-hidden=\"true\">✓</span> Copied";
      window.setTimeout(() => { button.innerHTML = "<span aria-hidden=\"true\">▣</span> Copy JSON"; }, 1600);
    } catch {
      const range = document.createRange();
      range.selectNodeContents(jsonOutput);
      const selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      errorMessage.textContent = "Clipboard access is unavailable here. Select the JSON report and copy it manually.";
      errorMessage.hidden = false;
    }
  });

  document.getElementById("download-report").addEventListener("click", () => {
    if (!currentReport) return;
    const blob = new Blob([`${JSON.stringify(currentReport, null, 2)}\n`], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "headerguard-report.json";
    link.click();
    URL.revokeObjectURL(url);
  });
})();
