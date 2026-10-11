// JavaScript source code
// Returns a list of reasons why the current URL looks suspicious
function checkUrl(urlString) {
  const reasons = [];
  const url = new URL(urlString);
  const host = url.hostname;

  // 1. Host is an IP address instead of a domain name
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    reasons.push("The address uses an IP number instead of a website name.");
  }

  // 2. Punycode (can disguise lookalike characters)
  if (host.includes("xn--")) {
    reasons.push("The domain uses encoded characters that can imitate real sites.");
  }

  // 3. '@' in the URL (can hide the real destination)
  if (urlString.includes("@")) {
    reasons.push("The URL contains an '@' symbol, which can hide the real destination.");
  }

  // 4. Too many subdomains (e.g. login.bank.example.evil.com)
  if (host.split(".").length > 4) {
    reasons.push("The domain has an unusually large number of subdomains.");
  }

  // 5. Not using HTTPS
  if (url.protocol === "http:") {
    reasons.push("The connection is not encrypted (HTTP, not HTTPS).");
  }

  return reasons;
}

// Shows a warning banner at the top of the page
function showWarning(reasons) {
  const banner = document.createElement("div");
  banner.style.cssText =
    "position:fixed;top:0;left:0;right:0;z-index:2147483647;" +
    "background:#b00020;color:#fff;padding:12px 16px;" +
    "font:14px Arial,sans-serif;";
  banner.innerHTML =
    "<strong>Warning: this page looks suspicious</strong><ul style='margin:6px 0 0 18px'>" +
    reasons.map((r) => `<li>${r}</li>`).join("") +
    "</ul>";
  document.body.prepend(banner);
}

const reasons = checkUrl(window.location.href);
console.log("Phishing Detector reasons:", reasons);
if (reasons.length > 0) {
  showWarning(reasons);
}