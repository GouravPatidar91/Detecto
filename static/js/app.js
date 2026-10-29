// Detecto Minimal & Clean Frontend Application Logic

const FEATURE_DESCRIPTIONS = {
  url_length: "Total character count of the full URL string.",
  hostname_length: "Length of the target domain / host.",
  path_length: "Length of resource path after domain.",
  query_length: "Length of dynamic GET parameters string.",
  count_dots: "Total period symbols (excessive in phishing).",
  count_slashes: "Forward slashes indicating URL directory depth.",
  count_hyphens: "Hyphens often used to disguise brand names.",
  count_underscores: "Underscore characters in URL structure.",
  count_question_marks: "Query delimiters in the URL.",
  count_equals: "Parameter assignments in query string.",
  count_ampersands: "Parameter chain separators.",
  count_at: "Userinfo / credentials delimiter '@' trick.",
  count_percent: "URL-encoded hexadecimal characters count.",
  count_exclamation: "Exclamation marks in URL string.",
  count_tilde: "Tilde characters indicating user directory paths.",
  count_digits: "Count of numeric digits (0-9) across URL.",
  digit_ratio: "Ratio of numbers to total characters in URL.",
  subdomain_count: "Levels of nested subdomains before main domain.",
  is_ip_address: "1 if host is raw numeric IP, 0 if domain name.",
  is_https: "1 if connection uses HTTPS, 0 if HTTP.",
  is_shortener: "1 if domain matches known URL shorteners.",
  is_suspicious_tld: "1 if domain uses a high-abuse TLD.",
  domain_has_hyphen: "1 if hostname contains hyphen (brand spoofing).",
  suspicious_keyword_count: "Matches against phishing trigger keywords.",
  has_custom_port: "1 if connecting over non-standard port.",
  domain_entropy: "Shannon entropy measuring domain randomness.",
  url_entropy: "Shannon entropy measuring full URL complexity."
};

let currentReportData = null;

document.addEventListener("DOMContentLoaded", () => {
  // Elements
  const scanForm = document.getElementById("scanForm");
  const urlInput = document.getElementById("urlInput");
  const btnClear = document.getElementById("btnClear");
  const liveProbeToggle = document.getElementById("liveProbeToggle");
  const btnScan = document.getElementById("btnScan");
  const scanSpinner = document.getElementById("scanSpinner");
  const samplePills = document.querySelectorAll(".pill");

  const resultsSection = document.getElementById("resultsSection");
  const verdictBadge = document.getElementById("verdictBadge");
  const verdictIcon = document.getElementById("verdictIcon");
  const verdictText = document.getElementById("verdictText");
  const resultUrl = document.getElementById("resultUrl");
  const resultMessage = document.getElementById("resultMessage");
  const riskScoreValue = document.getElementById("riskScoreValue");
  const gaugeFill = document.getElementById("gaugeFill");
  const confidenceTag = document.getElementById("confidenceTag");

  const dnsStatus = document.getElementById("dnsStatus");
  const sslStatus = document.getElementById("sslStatus");
  const typosquatStatus = document.getElementById("typosquatStatus");
  const domFormStatus = document.getElementById("domFormStatus");
  const redirectBanner = document.getElementById("redirectBanner");
  const redirectFinalUrl = document.getElementById("redirectFinalUrl");
  const reasonsList = document.getElementById("reasonsList");
  const featuresTableBody = document.getElementById("featuresTableBody");

  // Report Export Elements
  const btnCopyReport = document.getElementById("btnCopyReport");
  const btnExportJson = document.getElementById("btnExportJson");
  const btnPrintReport = document.getElementById("btnPrintReport");
  const toastNotification = document.getElementById("toastNotification");
  const toastMessage = document.getElementById("toastMessage");

  // History & Stats Elements
  const filterSelect = document.getElementById("filterSelect");
  const btnClearHistory = document.getElementById("btnClearHistory");
  const historyTableBody = document.getElementById("historyTableBody");

  // Load initial statistics and history
  loadStats();
  loadHistory();

  // Clear Input Button
  btnClear.addEventListener("click", () => {
    urlInput.value = "";
    urlInput.focus();
  });

  // Sample Pills Click Handler
  samplePills.forEach(pill => {
    pill.addEventListener("click", () => {
      const targetUrl = pill.getAttribute("data-url");
      urlInput.value = targetUrl;
      handleScan(targetUrl);
    });
  });

  // Form Submit Handler
  scanForm.addEventListener("submit", (e) => {
    e.preventDefault();
    const url = urlInput.value.trim();
    if (url) {
      handleScan(url);
    }
  });

  // Filter Dropdown Handler
  filterSelect.addEventListener("change", () => {
    loadHistory(filterSelect.value);
  });

  // Clear History Button
  btnClearHistory.addEventListener("click", async () => {
    if (confirm("Are you sure you want to clear all scan history?")) {
      try {
        await fetch("/api/history", { method: "DELETE" });
        loadHistory();
        loadStats();
        showToast("Scan audit history cleared.");
      } catch (err) {
        console.error("Failed to clear history:", err);
      }
    }
  });

  // Export: Copy Clean Summary to Clipboard
  btnCopyReport.addEventListener("click", () => {
    if (!currentReportData) return;
    const d = currentReportData;

    const reasonsText = d.risk_reasons && d.risk_reasons.length > 0 
      ? d.risk_reasons.map(r => `  • ${r}`).join("\n") 
      : "  • No adverse threat findings.";

    const reportSummary = `=====================================================
         DETECTO AI SECURITY AUDIT REPORT
=====================================================
Target URL:      ${d.url}
Verdict:         ${d.classification.toUpperCase()}
Risk Score:      ${d.risk_score}%
Confidence:      ${d.confidence}%
DNS Status:      ${d.dns_resolved ? `Resolved (${d.resolved_ip})` : 'Unresolved / Offline'}
SSL Encryption:  ${d.ssl_valid ? `Valid (${d.ssl_issuer})` : 'Invalid / Insecure HTTP'}
Typosquatting:   ${d.is_typosquatting ? `YES - Spoofs ${d.spoofed_brand.toUpperCase()}` : 'None (Authentic)'}
Credential Form: ${d.has_password_input ? 'YES (Password input detected)' : 'No password field'}
Audit Timestamp: ${d.scanned_at || new Date().toISOString()}

Diagnostic Findings:
${reasonsText}

Summary:
  ${d.status_message}
=====================================================`;

    navigator.clipboard.writeText(reportSummary).then(() => {
      showToast("Security summary copied to clipboard!");
    }).catch(() => {
      showToast("Failed to copy to clipboard.");
    });
  });

  // Export: Download JSON File
  btnExportJson.addEventListener("click", () => {
    if (!currentReportData) return;
    const jsonStr = JSON.stringify(currentReportData, null, 2);
    const blob = new Blob([jsonStr], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    const safeDomain = (currentReportData.domain || "report").replace(/[^a-zA-Z0-9_-]/g, "_");
    a.href = url;
    a.download = `detecto_audit_${safeDomain}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast("Audit JSON report downloaded!");
  });

  // Export: Print / PDF
  btnPrintReport.addEventListener("click", () => {
    window.print();
  });

  // Core Scan Function
  async function handleScan(url) {
    setLoading(true);

    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          url: url,
          live_probe: liveProbeToggle.checked
        })
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || "Scanning failed");
      }

      const data = await response.json();
      currentReportData = data;
      renderResults(data);
      loadStats();
      loadHistory(filterSelect.value);
    } catch (err) {
      alert(`Scan Error: ${err.message}`);
    } finally {
      setLoading(false);
    }
  }

  function setLoading(isLoading) {
    if (isLoading) {
      btnScan.disabled = true;
      scanSpinner.style.display = "inline-block";
    } else {
      btnScan.disabled = false;
      scanSpinner.style.display = "none";
    }
  }

  function renderResults(data) {
    resultsSection.classList.remove("hidden");

    // Scanned URL & Message
    resultUrl.textContent = data.url;
    resultMessage.textContent = data.status_message;

    // Verdict Badge & Gauge styling
    verdictBadge.className = "verdict-badge";
    if (data.classification === "Safe") {
      verdictBadge.classList.add("badge-safe");
      verdictIcon.textContent = "🛡️";
      verdictText.textContent = "VERIFIED SAFE";
      gaugeFill.style.stroke = "#059669";
    } else if (data.classification === "Suspicious") {
      verdictBadge.classList.add("badge-suspicious");
      verdictIcon.textContent = "⚠️";
      verdictText.textContent = "SUSPICIOUS";
      gaugeFill.style.stroke = "#d97706";
    } else {
      verdictBadge.classList.add("badge-malicious");
      verdictIcon.textContent = "🚨";
      verdictText.textContent = "MALICIOUS THREAT";
      gaugeFill.style.stroke = "#dc2626";
    }

    // Gauge calculation (circumference: 2 * pi * 42 ≈ 264)
    const circumference = 264;
    const offset = circumference - (data.risk_score / 100) * circumference;
    gaugeFill.style.strokeDashoffset = offset;
    riskScoreValue.textContent = `${data.risk_score}%`;
    confidenceTag.textContent = `Confidence: ${data.confidence}%`;

    // Telemetry items
    if (data.dns_resolved) {
      dnsStatus.textContent = `Resolved (${data.resolved_ip})`;
      dnsStatus.style.color = "#059669";
    } else if (data.live_probe_status === "bypassed") {
      dnsStatus.textContent = "Bypassed";
      dnsStatus.style.color = "#64748b";
    } else {
      dnsStatus.textContent = "Unresolved / Offline";
      dnsStatus.style.color = "#dc2626";
    }

    if (data.ssl_valid) {
      sslStatus.textContent = `Valid (${data.ssl_issuer || "Trusted CA"})`;
      sslStatus.style.color = "#059669";
    } else if (data.features.is_https === 0) {
      sslStatus.textContent = "Insecure (HTTP)";
      sslStatus.style.color = "#d97706";
    } else if (data.live_probe_status === "bypassed") {
      sslStatus.textContent = "Bypassed";
      sslStatus.style.color = "#64748b";
    } else {
      sslStatus.textContent = data.ssl_issuer || "Untrusted SSL";
      sslStatus.style.color = "#dc2626";
    }

    // Typosquatting Status
    if (data.is_typosquatting) {
      typosquatStatus.textContent = `Impersonates ${data.spoofed_brand?.toUpperCase()}`;
      typosquatStatus.style.color = "#dc2626";
    } else {
      typosquatStatus.textContent = "None (Authentic)";
      typosquatStatus.style.color = "#059669";
    }

    // HTML Credential Form Status
    if (data.brand_title_mismatch) {
      domFormStatus.textContent = "Title Brand Mismatch";
      domFormStatus.style.color = "#dc2626";
    } else if (data.has_password_input) {
      domFormStatus.textContent = "Password Form Found";
      domFormStatus.style.color = "#d97706";
    } else {
      domFormStatus.textContent = "No Password Form";
      domFormStatus.style.color = "#64748b";
    }

    // Redirect Banner
    if (data.is_redirected && data.url !== data.original_url) {
      redirectBanner.classList.remove("hidden");
      redirectFinalUrl.textContent = data.url;
    } else {
      redirectBanner.classList.add("hidden");
    }

    // Risk reasons
    reasonsList.innerHTML = "";
    if (data.risk_reasons && data.risk_reasons.length > 0) {
      data.risk_reasons.forEach(reason => {
        const li = document.createElement("li");
        li.textContent = reason;
        reasonsList.appendChild(li);
      });
    }

    // Feature Table
    featuresTableBody.innerHTML = "";
    if (data.features) {
      for (const [key, val] of Object.entries(data.features)) {
        const tr = document.createElement("tr");
        const desc = FEATURE_DESCRIPTIONS[key] || "Structural URL indicator";
        tr.innerHTML = `
          <td><code>${key}</code></td>
          <td>${val}</td>
          <td>${desc}</td>
        `;
        featuresTableBody.appendChild(tr);
      }
    }

    // Smooth scroll to results
    resultsSection.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  // Toast Notification Helper
  function showToast(message) {
    if (!toastNotification || !toastMessage) return;
    toastMessage.textContent = message;
    toastNotification.style.display = "flex";
    toastNotification.classList.remove("hidden");
    setTimeout(() => {
      toastNotification.classList.add("hidden");
      toastNotification.style.display = "none";
    }, 2800);
  }

  // Load Dashboard Stats
  async function loadStats() {
    try {
      const res = await fetch("/api/stats");
      if (res.ok) {
        const stats = await res.json();
        document.getElementById("statTotalScans").textContent = stats.total_scans;
        document.getElementById("statMaliciousCount").textContent = stats.malicious_scans;
        document.getElementById("statSuspiciousCount").textContent = stats.suspicious_scans;
        document.getElementById("statSafeCount").textContent = stats.safe_scans;
      }
    } catch (err) {
      console.error("Failed to load stats:", err);
    }
  }

  // Load Scan History
  async function loadHistory(filter = "") {
    try {
      let url = "/api/history?limit=30";
      if (filter) {
        url += `&filter_class=${encodeURIComponent(filter)}`;
      }

      const res = await fetch(url);
      if (res.ok) {
        const history = await res.json();
        if (history.length === 0) {
          historyTableBody.innerHTML = `
            <tr>
              <td colspan="8" class="empty-state" style="text-align: center; color: #64748b; padding: 2.5rem; font-style: italic;">No scans recorded in this filter.</td>
            </tr>
          `;
          return;
        }

        historyTableBody.innerHTML = "";
        history.forEach(item => {
          const tr = document.createElement("tr");
          const pillClass = item.classification.toLowerCase();
          const dnsBadge = item.dns_resolved 
            ? `<span class="audit-check-ok" title="Resolved">✓</span>` 
            : `<span class="audit-check-no" title="Unresolved">✗</span>`;
          const sslBadge = item.ssl_valid 
            ? `<span class="audit-check-ok" title="Valid SSL Certificate">✓</span>` 
            : `<span class="audit-check-no" title="No / Invalid SSL">✗</span>`;

          tr.innerHTML = `
            <td style="font-weight: 800; color: #64748b;">#${item.id}</td>
            <td style="max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${item.url}">
              <code style="background: #f1f5f9; padding: 0.25rem 0.5rem; border-radius: 6px; font-weight: 700; color: #1e293b;">${item.url}</code>
            </td>
            <td><span class="status-pill ${pillClass}">${item.classification}</span></td>
            <td><strong style="font-size: 1rem; color: #1e293b;">${item.risk_score}%</strong></td>
            <td>${dnsBadge}</td>
            <td>${sslBadge}</td>
            <td style="color: #64748b; font-size: 0.8rem; font-weight: 600;">${item.created_at}</td>
            <td>
              <button type="button" class="btn-inspect-action btn-link" data-rescan="${item.url}" title="Inspect this URL">
                <span>Inspect</span>
                <span class="inspect-arrow">↗</span>
              </button>
            </td>
          `;
          historyTableBody.appendChild(tr);
        });

        document.querySelectorAll("[data-rescan]").forEach(btn => {
          btn.addEventListener("click", () => {
            const urlToRescan = btn.getAttribute("data-rescan");
            urlInput.value = urlToRescan;
            handleScan(urlToRescan);
          });
        });
      }
    } catch (err) {
      console.error("Failed to load history:", err);
    }
  }
});
