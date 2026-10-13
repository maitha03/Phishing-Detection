<p align="center">
  <img src="icons/icon128.png" alt="LinkSentry logo" width="96">
</p>
<h1 align="center">LinkSentry</h1>
<p align="center">
  A browser extension that analyzes the address of every page you visit and warns you when it looks like phishing.
</p>
---
What it does
LinkSentry reads the URL of each page as you browse and scores it against a set of phishing indicators. When the score passes a threshold, a warning banner appears at the top of the page showing the risk score and exactly why the page was flagged, so you can judge the warning yourself instead of trusting a black box.
All analysis runs locally in your browser. No URLs, page content or browsing history are sent anywhere.
Features
Weighted risk scoring: each signal adds points, and a warning appears only when the total is high enough. One weak signal on its own (such as plain HTTP) does not trigger an alert.
Explainable warnings: the banner lists every reason with the points it contributed.
Two alert levels: orange for suspicious and red for high risk.
Look-alike domain detection: catches `paypa1.com`, `g00gle.com`, `gooogle.com` and similar typosquats of well-known brands.
Homograph detection: decodes punycode (`xn--`) domains, flags mixed alphabets, and maps look-alike characters (for example Cyrillic "а" vs. Latin "a") to the letters they imitate.
IP address tricks: flags raw IPs and disguised forms such as `http://3232235777`.
URL tricks: detects fake usernames in the address (`https://paypal.com@evil.com`), brands placed in subdomains (`paypal.com.evil.net`), embedded redirect URLs, shorteners, deep subdomain chains and unusual ports.
Reputation signals: frequently abused domain endings, free hosting services, auto-generated-looking names and sensitive words (`login`, `verify`, `secure`).
Built-in self-test: a table of sample URLs with expected outcomes, printed to the console.
How the scoring works
Score	Result
0 to 2	No warning
3 to 5	Orange banner: Caution, this page looks suspicious
6 and above	Red banner: High risk
Examples of signals and their weights:
Signal	Points
Look-alike characters imitating a known brand (`paypa1.com`)	+4
Real brand domain placed in a subdomain (`paypal.com.evil.net`)	+4
IP address instead of a domain name	+3
Mixed alphabets in one domain label	+3
Username part in the address (`@` trick)	+3
One character away from a known brand (`gooogle.com`)	+3
Brand name buried in the domain (`paypal-secure-login.com`)	+2
Disguised IP address	+2
Unencrypted connection (HTTP)	+1
Unusual port	+1
URL shortener	+1
Free hosting service	+1
Domains that belong to a known brand (for example `login.microsoftonline.com`) are trusted and skip the heuristics. The full rule set and weights are in `content.js`.
Install (developer mode)
Clone or download this repository:
```bash
   git clone https://github.com/maitha03/Phishing-Detection.git
   ```
Open `chrome://extensions` in Chrome (or any Chromium-based browser).
Turn on Developer mode (top right).
Click Load unpacked and select the project folder.
Pin LinkSentry from the puzzle-piece menu if you like.
After you change any code, click the reload icon on the extension's card and refresh the page.
Try it safely
You never need to visit a real phishing site to test the extension.
Run the self-test. With `DEBUG = true` in `content.js`, open any page, press `Ctrl + Shift + J`, and look at the console table. Each sample URL is analyzed (not visited) and marked `PASS` or `FAIL` against its expected result.
Trigger a warning locally. From any empty folder, run:
```bash
python -m http.server 8000
```
Then open `http://127.0.0.1:8000`. The page scores 5 (IP address, HTTP and an unusual port), so the orange banner appears.
Project structure
```
.
├── manifest.json     # Extension configuration (Manifest V3)
├── content.js        # URL analysis, scoring, warning banner, self-test
├── icons/            # Extension icons (16, 32, 48, 128 px)
└── README.md
```
Limitations
The analysis is heuristic, so it will produce some false positives and some misses. It is a warning aid, not a guarantee of safety.
It only inspects the URL. It does not yet analyze page content (such as login forms) or check domain age.
The brand list is limited and the domain-ending list is a short approximation of the full Public Suffix List.
Attackers who know the rules can evade them.
Roadmap
[ ] Evaluate the rules on public datasets of phishing and legitimate URLs (precision, recall and false-positive rate)
[ ] Add page-content signals (password fields posting to another domain, hidden iframes, mismatched link text)
[ ] Look up URLs against a reputation feed such as Google Safe Browsing
[ ] Train and compare a machine-learning classifier against the rule-based baseline
[ ] Toolbar popup with details and a per-site allowlist
[ ] Automated unit tests and CI
[ ] Firefox build and Chrome Web Store listing
Tech
JavaScript (ES2020), Chrome Extension Manifest V3. No external dependencies.
Author
 **Maythaa Almukhaini** - Cybersecurity & Machine Learning Developer
 **GitHub:**  @maitha03 (https://github.com/yourusername)
 **LinkedIn:** [Maithaa Almukhaini](https://linkedin.com/in/Maithaa Almukhaini)
 **Email:** maythaalmukaini@example.com

Built as a post-graduation project.
License
MIT License

Copyright (c) 2026 Maythaa Almukhaini

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
