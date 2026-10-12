// Phishing Detector - content.js (advanced URL analysis)

const WARNING_THRESHOLD = 3;
const HIGH_RISK_THRESHOLD = 6;
const DEBUG = true; // prints a self-test table in the console; set to false later
const USER_ALLOWLIST = []; // sites you always trust, e.g. ["myuniversity.edu"]

// =====================================================================
// Data
// =====================================================================

// Brands that phishers imitate, with their real domains
const BRANDS = {
  paypal: ["paypal.com", "paypal.me"],
  google: ["google.com", "gmail.com", "youtube.com", "googleapis.com", "gstatic.com", "googleusercontent.com"],
  microsoft: ["microsoft.com", "microsoftonline.com", "live.com", "office.com", "office365.com", "outlook.com", "bing.com", "windows.com", "azure.com", "sharepoint.com", "msn.com"],
  apple: ["apple.com", "icloud.com"],
  amazon: ["amazon.com", "amazonaws.com", "primevideo.com"],
  facebook: ["facebook.com", "fb.com", "messenger.com"],
  instagram: ["instagram.com"],
  whatsapp: ["whatsapp.com", "whatsapp.net"],
  twitter: ["twitter.com", "x.com"],
  linkedin: ["linkedin.com", "licdn.com"],
  netflix: ["netflix.com"],
  spotify: ["spotify.com"],
  github: ["github.com", "githubusercontent.com"],
  dropbox: ["dropbox.com"],
  adobe: ["adobe.com"],
  docusign: ["docusign.com", "docusign.net"],
  coinbase: ["coinbase.com"],
  binance: ["binance.com"],
  ebay: ["ebay.com"],
  yahoo: ["yahoo.com"],
  telegram: ["telegram.org", "t.me"],
  discord: ["discord.com", "discord.gg"],
  steam: ["steampowered.com", "steamcommunity.com"],
  chase: ["chase.com"],
  wellsfargo: ["wellsfargo.com"],
  bankofamerica: ["bankofamerica.com"],
  hsbc: ["hsbc.com"],
  fedex: ["fedex.com"],
};

// Every real brand domain is trusted (plus your own allowlist)
const LEGIT = new Set([...Object.values(BRANDS).flat(), ...USER_ALLOWLIST]);

// Endings where the registrable domain has one more label (example.co.uk)
const MULTI_SUFFIXES = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz",
  "co.jp", "co.in", "co.za", "co.kr", "com.br", "com.cn", "com.mx", "com.tr",
  "com.sa", "com.om", "org.om", "gov.om", "edu.om", "com.kw", "com.qa", "com.bh",
  "co.ae", "com.eg", "com.sg", "com.hk", "com.pk", "com.my", "com.ng", "com.ar",
  "com.ua", "com.pl",
]);

// Free hosting / dynamic DNS: anyone can create a subdomain here
const FREE_HOSTS = new Set([
  "github.io", "pages.dev", "web.app", "firebaseapp.com", "netlify.app",
  "vercel.app", "herokuapp.com", "blogspot.com", "weebly.com", "wixsite.com",
  "workers.dev", "glitch.me", "repl.co", "000webhostapp.com", "ngrok.io",
  "ngrok-free.app", "trycloudflare.com", "azurewebsites.net", "webflow.io",
  "carrd.co", "duckdns.org", "no-ip.org", "ddns.net", "myftpupload.com",
]);

const SUSPICIOUS_TLDS = new Set([
  "tk", "ml", "ga", "cf", "gq", "top", "xyz", "click", "country", "work",
  "support", "loan", "icu", "cam", "rest", "buzz", "monster", "cyou", "sbs",
  "zip", "mov",
]);

const SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
  "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "t.ly", "lnkd.in", "s.id",
]);

const SENSITIVE_WORDS = [
  "login", "signin", "sign-in", "verify", "verification", "secure", "security",
  "account", "update", "confirm", "banking", "password", "wallet", "support",
  "billing", "invoice", "suspend", "unlock", "recover", "authenticate", "webscr", "alert",
];

// Characters from other alphabets that look like Latin letters
const CONFUSABLES = {
  "\u0430": "a", "\u0435": "e", "\u043E": "o", "\u0440": "p", "\u0441": "c",
  "\u0445": "x", "\u0443": "y", "\u0456": "i", "\u0458": "j", "\u0455": "s",
  "\u04BB": "h", "\u0501": "d", "\u051B": "q", "\u051D": "w", "\u04CF": "l",
  "\u03BF": "o", "\u03BD": "v", "\u03B1": "a", "\u03C1": "p", "\u03B5": "e",
  "\u03B9": "i", "\u03BA": "k", "\u03C5": "u", "\u03C7": "x", "\u0131": "i",
  "\u2113": "l", "\u0261": "g", "\u0251": "a",
};

// =====================================================================
// Helpers
// =====================================================================

// Decodes the punycode part of a label (the text after "xn--"). Returns null on failure.
function punycodeDecode(input) {
  const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700;
  const initialBias = 72, initialN = 128, baseMinusTMin = base - tMin;

  const adapt = (delta, numPoints, firstTime) => {
    let k = 0;
    delta = firstTime ? Math.floor(delta / damp) : delta >> 1;
    delta += Math.floor(delta / numPoints);
    for (; delta > (baseMinusTMin * tMax) >> 1; k += base) {
      delta = Math.floor(delta / baseMinusTMin);
    }
    return Math.floor(k + ((baseMinusTMin + 1) * delta) / (delta + skew));
  };

  const toDigit = (cp) => {
    if (cp >= 0x30 && cp < 0x3a) return 26 + (cp - 0x30);
    if (cp >= 0x41 && cp < 0x5b) return cp - 0x41;
    if (cp >= 0x61 && cp < 0x7b) return cp - 0x61;
    return base;
  };

  try {
    const output = [];
    let n = initialN, i = 0, bias = initialBias;
    let basic = input.lastIndexOf("-");
    if (basic < 0) basic = 0;
    for (let j = 0; j < basic; j++) output.push(input.charCodeAt(j));

    for (let index = basic > 0 ? basic + 1 : 0; index < input.length; ) {
      const oldi = i;
      for (let w = 1, k = base; ; k += base) {
        if (index >= input.length) return null;
        const digit = toDigit(input.charCodeAt(index++));
        if (digit >= base) return null;
        i += digit * w;
        const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
        if (digit < t) break;
        w *= base - t;
      }
      const out = output.length + 1;
      bias = adapt(i - oldi, out, oldi === 0);
      n += Math.floor(i / out);
      i %= out;
      output.splice(i++, 0, n);
    }
    return String.fromCodePoint(...output);
  } catch {
    return null;
  }
}

// "xn--80ak6aa92e.com" -> the Unicode version of the hostname
function decodeHost(host) {
  return host
    .split(".")
    .map((label) => {
      if (!label.startsWith("xn--")) return label;
      const decoded = punycodeDecode(label.slice(4));
      return decoded === null ? label : decoded;
    })
    .join(".");
}

// Which alphabets does a label use? (digits and hyphens are neutral)
function scriptsIn(label) {
  const found = new Set();
  for (const ch of label) {
    if (/[a-z]/i.test(ch) || /[\u00C0-\u024F]/.test(ch)) found.add("Latin");
    else if (/[\u0370-\u03FF]/.test(ch)) found.add("Greek");
    else if (/[\u0400-\u052F]/.test(ch)) found.add("Cyrillic");
    else if (/[\u0590-\u05FF]/.test(ch)) found.add("Hebrew");
    else if (/[\u0600-\u06FF\u0750-\u077F]/.test(ch)) found.add("Arabic");
    else if (/[\u3040-\u30FF\u4E00-\u9FFF\uAC00-\uD7AF]/.test(ch)) found.add("CJK");
    else if (/[0-9-]/.test(ch)) continue;
    else found.add("Other");
  }
  return found;
}

// Reduces text to a "skeleton" so look-alikes collapse to the same string:
// paypa1 / paypaI / pаypal (Cyrillic а) all become the skeleton of "paypal".
function skeleton(text) {
  let s = text.normalize("NFKD").replace(/[\u0300-\u036f]/g, "").toLowerCase();
  s = Array.from(s, (c) => CONFUSABLES[c] || c).join("");
  s = s.replace(/[-_]/g, "");
  s = s.replace(/0/g, "o").replace(/1/g, "l").replace(/3/g, "e")
       .replace(/4/g, "a").replace(/5/g, "s").replace(/7/g, "t").replace(/8/g, "b");
  s = s.replace(/rn/g, "m").replace(/vv/g, "w").replace(/cl/g, "d");
  s = s.replace(/i/g, "l");
  return s;
}

// Edit distance that also counts swapped neighbours as one edit (paypla -> paypal)
function editDistance(a, b) {
  const d = Array.from({ length: a.length + 1 }, (_, i) => {
    const row = new Array(b.length + 1).fill(0);
    row[0] = i;
    return row;
  });
  for (let j = 0; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
      }
    }
  }
  return d[a.length][b.length];
}

// Splits a hostname into registrable domain, name, ending and subdomain
function splitHost(host) {
  const labels = host.split(".");
  const last2 = labels.slice(-2).join(".");
  const onFreeHost = FREE_HOSTS.has(last2);
  const suffixLen = onFreeHost || MULTI_SUFFIXES.has(last2) ? 2 : 1;
  const domainLen = Math.min(labels.length, suffixLen + 1);
  const domainLabels = labels.slice(-domainLen);
  return {
    domain: domainLabels.join("."),
    name: domainLabels[0],
    tld: labels[labels.length - 1],
    subdomain: labels.slice(0, labels.length - domainLen).join("."),
    onFreeHost,
  };
}

// Host exactly as typed (the URL parser rewrites things like http://3232235777)
function getRawHost(urlString) {
  const m = urlString.match(/^[a-z][a-z0-9+.\-]*:\/\/(?:[^\/?#@]*@)?([^\/?#:]*)/i);
  return m ? m[1].toLowerCase() : "";
}

function decodeSafe(s) {
  try { return decodeURIComponent(s); } catch { return s; }
}

// Long, vowel-poor or digit-heavy names often come from auto-generated domains
function looksRandom(name) {
  if (name.length < 10 || !/^[a-z0-9-]+$/.test(name)) return false;
  const letters = name.replace(/[^a-z]/g, "");
  const digitRatio = (name.match(/\d/g) || []).length / name.length;
  const vowelRatio = (letters.match(/[aeiou]/g) || []).length / Math.max(letters.length, 1);
  return digitRatio > 0.3 || vowelRatio < 0.2 || /[bcdfghjklmnpqrstvwxyz]{6,}/.test(name);
}

// =====================================================================
// Brand impersonation (returns the single strongest finding, or null)
// =====================================================================

function analyzeBrand(parts) {
  const nameNoHyphen = parts.name.replace(/-/g, "");
  const nameSkel = skeleton(parts.name);
  const subSkel = skeleton(parts.subdomain.replace(/\./g, ""));
  const candidates = [];
  const add = (weight, reason) => candidates.push({ weight, reason });

  for (const [brand, domains] of Object.entries(BRANDS)) {
    if (brand.length < 4) continue;
    const brandSkel = skeleton(brand);
    const real = domains[0];

    if (parts.name !== brand && nameSkel === brandSkel) {
      // paypa1.com, g00gle.com, Cyrillic look-alikes
      add(4, `"${parts.domain}" is a look-alike of ${real}: characters are swapped for similar-looking ones.`);
    } else if (parts.name === brand) {
      // Same name, different domain. Regional sites (amazon.de) are fine.
      if (parts.onFreeHost) {
        add(3, `"${parts.domain}" uses the ${brand} name on a free hosting service.`);
      } else if (SUSPICIOUS_TLDS.has(parts.tld)) {
        add(2, `"${parts.domain}" uses the ${brand} name with an unusual ending (.${parts.tld}).`);
      }
    } else if (brand.length >= 6) {
      // Typosquatting: gooogle.com, paypall.com, paypla.com
      const dist = editDistance(nameNoHyphen, brand);
      const maxDist = brand.length >= 9 ? 2 : 1;
      if (dist <= maxDist) {
        add(dist === 1 ? 3 : 2, `"${parts.domain}" is almost identical to ${real} (${dist} character${dist > 1 ? "s" : ""} different).`);
      }
    }

    // Combo-squatting: paypal-secure-login.com
    if (brand.length >= 5 && parts.name !== brand && nameSkel !== brandSkel && nameSkel.includes(brandSkel)) {
      add(2, `"${parts.domain}" contains the brand name "${brand}" but is not ${real}.`);
    }

    // Brand placed in the subdomain: paypal.com.evil.net, login.paypal.evil.net
    if (subSkel.includes(brandSkel)) {
      if (parts.subdomain.includes(real)) {
        add(4, `The address puts "${real}" in the subdomain, but the real site is ${parts.domain}.`);
      } else {
        add(3, `The address uses "${brand}" in a subdomain of a different site (${parts.domain}).`);
      }
    }
  }

  candidates.sort((a, b) => b.weight - a.weight);
  return candidates[0] || null;
}

// =====================================================================
// Main analysis
// =====================================================================

function analyzeUrl(urlString) {
  const findings = [];
  const add = (weight, reason) => findings.push({ weight, reason });

  let url;
  try { url = new URL(urlString); } catch { return { score: 0, findings }; }
  if (!/^https?:$/.test(url.protocol)) return { score: 0, findings };

  const host = url.hostname.toLowerCase();
  const rawHost = getRawHost(urlString);
  const isIpv6 = host.startsWith("[");
  const isIpv4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
  const isIp = isIpv4 || isIpv6;
  const pathAndQuery = decodeSafe(url.pathname + url.search).toLowerCase();

  // ---- Connection ----
  if (url.protocol === "http:") add(1, "The connection is not encrypted (HTTP, not HTTPS).");
  if (url.port) add(1, `The site uses an unusual port (${url.port}).`);

  // ---- '@' trick: https://paypal.com@evil.com ----
  if (url.username || url.password) {
    const looksLikeSite = /\./.test(url.username + url.password);
    add(
      looksLikeSite ? 4 : 3,
      looksLikeSite
        ? `The address starts with a fake "username" that looks like a website; the real destination is ${host}.`
        : "The address contains a username/password part ('@'), which can hide the real destination."
    );
  }

  // ---- Hidden characters in the host ----
  if (rawHost.includes("%")) add(2, "The domain contains percent-encoded characters.");

  // ---- IP addresses ----
  if (isIp) {
    add(3, "The address uses an IP number instead of a website name.");
    if (isIpv4 && rawHost && rawHost !== host) {
      add(2, `The IP address is written in a disguised form (${rawHost}).`);
    }
  }

  let trusted = false;

  if (!isIp) {
    const decodedHost = decodeHost(host);
    const parts = splitHost(decodedHost);
    trusted = LEGIT.has(parts.domain);

    if (SHORTENERS.has(parts.domain)) {
      add(1, "The link goes through a URL shortener, which hides the real destination.");
    }

    if (!trusted) {
      // ---- Alphabets ----
      const labels = decodedHost.split(".");
      const mixed = labels.find((l) => scriptsIn(l).size > 1);
      if (mixed) {
        add(3, `The domain mixes alphabets (${[...scriptsIn(mixed)].join(" + ")}), a trick used to fake familiar names.`);
      }
      if (labels.some((l) => l.startsWith("xn--"))) {
        add(1, "The domain uses encoded characters that could not be decoded.");
      }

      // ---- Brand impersonation ----
      const brandFinding = analyzeBrand(parts);
      if (brandFinding) {
        add(brandFinding.weight, brandFinding.reason);
      } else {
        const brandInPath = Object.keys(BRANDS).find((b) => b.length >= 5 && pathAndQuery.includes(b));
        if (brandInPath) {
          add(1, `The page address mentions "${brandInPath}", but the site is ${parts.domain}.`);
        }
      }

      // ---- Domain reputation signals ----
      if (SUSPICIOUS_TLDS.has(parts.tld)) {
        const fileLike = parts.tld === "zip" || parts.tld === "mov";
        add(
          fileLike ? 2 : 1,
          fileLike
            ? `The ending ".${parts.tld}" looks like a file name and is often used to disguise links.`
            : `The domain ending ".${parts.tld}" is frequently abused for scams.`
        );
      }
      if (parts.onFreeHost) {
        add(1, `"${parts.domain}" is on a free hosting service that anyone can use.`);
      }

      // ---- Sensitive words in the domain ----
      const hostText = (parts.subdomain ? parts.subdomain + "." : "") + parts.name;
      const hostWords = SENSITIVE_WORDS.filter((w) => hostText.includes(w));
      if (hostWords.length) {
        add(Math.min(hostWords.length, 2), `The domain contains sensitive words (${hostWords.slice(0, 3).join(", ")}).`);
      }

      // ---- Structure ----
      if (parts.subdomain && parts.subdomain.split(".").length >= 4) {
        add(1, "The domain has an unusually deep chain of subdomains.");
      }
      if (decodedHost.length > 45) add(1, "The domain name is unusually long.");
      if ((parts.name.match(/-/g) || []).length >= 3) add(1, "The domain name contains many hyphens.");
      if (looksRandom(parts.name)) add(1, "The domain name looks randomly generated.");
    }
  }

  // ---- Path and URL-wide checks (not for trusted sites) ----
  if (!trusted) {
    const pathWords = SENSITIVE_WORDS.filter((w) => pathAndQuery.includes(w));
    if (pathWords.length >= 2) {
      add(1, `The page address asks for sensitive actions (${pathWords.slice(0, 3).join(", ")}).`);
    }
    if (/https?:\/\//.test(pathAndQuery)) {
      add(1, "The address contains another web address inside it (common in redirects).");
    }
    if (urlString.length > 100) add(1, "The address is unusually long.");
  }

  const score = findings.reduce((total, f) => total + f.weight, 0);
  return { score, findings };
}

// =====================================================================
// Warning banner (built with textContent, so page data can never inject HTML)
// =====================================================================

function showWarning(score, findings) {
  if (document.getElementById("phishing-detector-banner")) return;
  const high = score >= HIGH_RISK_THRESHOLD;

  const banner = document.createElement("div");
  banner.id = "phishing-detector-banner";
  banner.style.cssText =
    "position:fixed;top:0;left:0;right:0;z-index:2147483647;padding:12px 16px;" +
    "color:#fff;font:14px Arial,sans-serif;box-shadow:0 2px 8px rgba(0,0,0,.4);" +
    `background:${high ? "#b00020" : "#c75000"};`;

  const title = document.createElement("strong");
  title.textContent = high
    ? "High risk: this page shows strong signs of phishing"
    : "Caution: this page looks suspicious";

  const scoreLine = document.createElement("div");
  scoreLine.style.marginTop = "4px";
  scoreLine.textContent =
    `Risk score: ${score} (warning at ${WARNING_THRESHOLD}+, high risk at ${HIGH_RISK_THRESHOLD}+)`;

  const list = document.createElement("ul");
  list.style.margin = "6px 0 0 18px";
  [...findings]
    .sort((a, b) => b.weight - a.weight)
    .forEach((f) => {
      const li = document.createElement("li");
      li.textContent = `${f.reason} (+${f.weight})`;
      list.appendChild(li);
    });

  const close = document.createElement("button");
  close.textContent = "Dismiss";
  close.style.cssText = "position:absolute;top:10px;right:12px;padding:4px 10px;cursor:pointer;";
  close.addEventListener("click", () => banner.remove());

  banner.append(title, scoreLine, list, close);
  document.body.prepend(banner);
}

// =====================================================================
// Self-test: checks the rules against sample URLs (nothing is visited)
// =====================================================================

const TESTS = [
  // [url, should it trigger a warning?]
  ["https://www.paypal.com/signin", false],
  ["https://www.google.com/search?q=login+verify", false],
  ["https://accounts.google.com/ServiceLogin", false],
  ["https://github.com/login", false],
  ["https://mail.google.com/mail/u/0/", false],
  ["https://www.amazon.de/", false],
  ["https://www.google.co.uk/", false],
  ["https://www.bbc.co.uk/news", false],
  ["https://example.com/", false],
  ["http://example.com/", false],
  ["https://bit.ly/3xYzAbc", false],
  ["https://news.ycombinator.com/", false],
  ["https://stackoverflow.com/questions/12345/how-to-login", false],
  ["https://www.wikipedia.org/wiki/PayPal", false],
  ["https://paypa1.com/login", true],
  ["https://g00gle.com/", true],
  ["https://gooogle.com/", true],
  ["https://paypal-secure-login.com/", true],
  ["https://paypal.com.evil-site.net/", true],
  ["https://secure.paypal.com@evil.com/login", true],
  ["http://192.168.1.1/login", true],
  ["http://3232235777/", true],
  ["http://127.0.0.1:8000/", true],
  ["https://xn--80ak6aa92e.com/", true],
  ["https://p\u0430ypal.com/", true],
  ["http://login-verify-account.xyz/update", true],
  ["https://microsoft-support.top/", true],
  ["https://google-login.web.app/", true],
];

function runSelfTest() {
  const rows = TESTS.map(([u, expectWarn]) => {
    const r = analyzeUrl(u);
    const warned = r.score >= WARNING_THRESHOLD;
    return {
      url: u,
      score: r.score,
      expected: expectWarn ? "warn" : "safe",
      result: warned === expectWarn ? "PASS" : "FAIL",
    };
  });
  console.table(rows);
}

// =====================================================================
// Run
// =====================================================================

const result = analyzeUrl(window.location.href);
console.log("Phishing Detector score:", result.score, result.findings);
if (result.score >= WARNING_THRESHOLD) {
  showWarning(result.score, result.findings);
}
if (DEBUG) runSelfTest();