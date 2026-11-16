#!/usr/bin/env python3
"""
Email Risk Analyzer (task3)

Scans email content (plain text, HTML, or .eml files) and flags potentially
unsafe messages by detecting suspicious patterns:

  * Urgency / pressure language
  * Requests for sensitive data (passwords, OTPs, card numbers, SSN...)
  * Suspicious or unknown links (IP URLs, shorteners, look-alike domains,
    mismatched link text, risky TLDs, '@' tricks, punycode)
  * Sender anomalies (display-name spoofing, Reply-To mismatch)
  * Risky attachments (.exe, .scr, .js, macro-enabled docs...)
  * Threats, prize/lottery lures, generic greetings

Usage:
    python email_risk_analyzer.py --demo
    python email_risk_analyzer.py message.eml
    python email_risk_analyzer.py message.txt --json
    cat message.eml | python email_risk_analyzer.py -
    python email_risk_analyzer.py message.eml --trusted mycompany.com bank.com

Only the Python standard library is required.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field, asdict
from email import policy
from email.parser import BytesParser, Parser
from html.parser import HTMLParser
from urllib.parse import urlparse

# --------------------------------------------------------------------------
# Configuration: patterns and weights
# --------------------------------------------------------------------------

URGENCY_PATTERNS = [
    r"\burgent(ly)?\b", r"\bimmediate(ly)?\b", r"\basap\b", r"\bact now\b",
    r"\bright away\b", r"\bwithin (the next )?\d+ ?(hours?|hrs?|minutes?|mins?)\b",
    r"\b(final|last) (notice|warning|reminder|chance)\b",
    r"\baccount (will be|has been) (suspended|locked|closed|disabled|terminated)\b",
    r"\bverify (your account )?(now|immediately|today)\b",
    r"\bexpires? (today|soon|in \d+)\b", r"\bfailure to (comply|respond|verify)\b",
    r"\bunauthori[sz]ed (login|access|activity|transaction)\b",
    r"\blimited time\b", r"\bdon'?t delay\b",
]

SENSITIVE_PATTERNS = [
    r"\b(confirm|verify|update|provide|enter|send|reply with|share)\b.{0,40}\b(password|passcode|pin)\b",
    r"\b(confirm|verify|update|provide|enter|send|reply with|share)\b.{0,40}\b(credit|debit) card\b",
    r"\b(confirm|verify|update|provide|enter|send|reply with|share)\b.{0,40}\b(bank|account) (details|number|information)\b",
    r"\b(social security|ssn|aadhaar|aadhar|pan card|passport) (number|no\.?|details)?\b",
    r"\b(otp|one[- ]time (password|code)|verification code|security code|cvv|cvc)\b",
    r"\blog ?in (to|with) (your )?(account|credentials)\b",
    r"\b(card|account) (number|details)\b",
    r"\bseed phrase\b|\brecovery phrase\b|\bprivate key\b",
    r"\bwire transfer\b|\bgift cards?\b|\bbitcoin\b|\bcrypto(currency)? wallet\b",
]

LURE_PATTERNS = [
    r"\byou('ve| have)? (won|been selected)\b", r"\blottery\b", r"\bprize\b",
    r"\bclaim your (reward|gift|refund|prize)\b", r"\binheritance\b",
    r"\bunclaimed (funds|refund|money)\b", r"\bcongratulations\b",
    r"\bmillion (dollars|usd|pounds)\b",
]

THREAT_PATTERNS = [
    r"\blegal action\b", r"\barrest(ed)?\b", r"\bpenalt(y|ies)\b",
    r"\bsuspend(ed)?\b", r"\bterminated?\b", r"\bpolice\b", r"\bfine of\b",
]

GENERIC_GREETINGS = [
    r"^\s*dear (customer|user|client|member|valued customer|account holder|sir|madam|sir/madam)\b",
    r"^\s*hello (user|customer|dear)\b", r"^\s*attention\b",
]

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "t.ly",
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml", "cf",
    "ga", "work", "support", "rest", "fit", "loan", "men", "review", "icu",
    "monster", "buzz", "cam", "live",
}

RISKY_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".js", ".jse", ".vbs",
    ".vbe", ".wsf", ".ps1", ".jar", ".msi", ".lnk", ".iso", ".img", ".hta",
    ".docm", ".xlsm", ".pptm", ".dll", ".apk",
}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".gz", ".tar"}

# Brands commonly impersonated (used for look-alike / spoof detection)
KNOWN_BRANDS = {
    "paypal": "paypal.com", "microsoft": "microsoft.com", "apple": "apple.com",
    "google": "google.com", "amazon": "amazon.com", "netflix": "netflix.com",
    "facebook": "facebook.com", "instagram": "instagram.com",
    "linkedin": "linkedin.com", "dhl": "dhl.com", "fedex": "fedex.com",
    "sbi": "sbi.co.in", "hdfc": "hdfcbank.com", "icici": "icicibank.com",
    "chase": "chase.com", "wells fargo": "wellsfargo.com",
}

# Points added per finding category (capped per category to avoid runaway scores)
WEIGHTS = {
    "urgency":        (8, 24),   # (points per hit, cap)
    "sensitive":      (14, 42),
    "lure":           (8, 16),
    "threat":         (5, 10),
    "greeting":       (6, 6),
    "caps_exclaim":   (5, 5),
}

RISK_LEVELS = [  # (min score, label)
    (60, "HIGH"),
    (30, "MEDIUM"),
    (10, "LOW"),
    (0, "SAFE"),
]

# --------------------------------------------------------------------------
# Data structures
# --------------------------------------------------------------------------

@dataclass
class Finding:
    category: str
    description: str
    points: int
    evidence: str = ""


@dataclass
class Report:
    score: int = 0
    level: str = "SAFE"
    findings: list[Finding] = field(default_factory=list)
    links: list[str] = field(default_factory=list)

    def add(self, category: str, description: str, points: int, evidence: str = ""):
        self.findings.append(Finding(category, description, points, evidence[:120]))


@dataclass
class ParsedEmail:
    sender: str = ""
    reply_to: str = ""
    subject: str = ""
    body_text: str = ""
    # list of (href, visible_text) from HTML parts
    html_links: list[tuple[str, str]] = field(default_factory=list)
    attachments: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------

class _LinkExtractor(HTMLParser):
    """Extracts visible text and <a href> pairs from HTML."""

    def __init__(self):
        super().__init__()
        self.text: list[str] = []
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._buf: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
        if tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._buf = []

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._buf).strip()))
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        self.text.append(data)
        if self._href is not None:
            self._buf.append(data)


def parse_email(raw: str | bytes) -> ParsedEmail:
    """Parse raw RFC-822 text or a bare message body into a ParsedEmail."""
    if isinstance(raw, bytes):
        msg = BytesParser(policy=policy.default).parsebytes(raw)
    else:
        msg = Parser(policy=policy.default).parsestr(raw)

    pe = ParsedEmail(
        sender=str(msg.get("From", "") or ""),
        reply_to=str(msg.get("Reply-To", "") or ""),
        subject=str(msg.get("Subject", "") or ""),
    )

    # Plain input with no headers: treat everything as the body.
    if not msg.keys():
        raw_text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
        _ingest_body(pe, raw_text, is_html="<a " in raw_text.lower() or "<html" in raw_text.lower())
        return pe

    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if filename:
            pe.attachments.append(filename)
            continue
        ctype = part.get_content_type()
        if ctype in ("text/plain", "text/html"):
            try:
                content = part.get_content()
            except Exception:
                content = ""
            _ingest_body(pe, content, is_html=(ctype == "text/html"))
    return pe


def _ingest_body(pe: ParsedEmail, content: str, is_html: bool):
    if is_html:
        ex = _LinkExtractor()
        ex.feed(content)
        pe.html_links.extend(ex.links)
        pe.body_text += " ".join(ex.text) + "\n"
    else:
        pe.body_text += content + "\n"


# --------------------------------------------------------------------------
# Detection helpers
# --------------------------------------------------------------------------

URL_RE = re.compile(r"""(?i)\b((?:https?://|www\.)[^\s<>"'()\[\]]+)""")
EMAIL_ADDR_RE = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")
IP_HOST_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _domain_of(address: str) -> str:
    m = EMAIL_ADDR_RE.search(address or "")
    return m.group(1).lower() if m else ""


def _display_name(address: str) -> str:
    return re.sub(r"<.*?>", "", address or "").strip(' "').lower()


def _host(url: str) -> str:
    if not re.match(r"(?i)^https?://", url):
        url = "http://" + url
    return (urlparse(url).hostname or "").lower()


def _root_domain(host: str) -> str:
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "gov", "ac") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _is_trusted(host: str, trusted: set[str]) -> bool:
    root = _root_domain(host)
    return root in trusted or host in trusted


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _lookalike_brand(host: str) -> str | None:
    """Return the brand a host appears to imitate (but isn't)."""
    root = _root_domain(host)
    label = root.split(".")[0]
    # Normalise common character swaps (0->o, 1->l, rn->m ...)
    norm = label.replace("0", "o").replace("1", "l").replace("rn", "m").replace("vv", "w")
    for brand, real in KNOWN_BRANDS.items():
        brand_key = brand.replace(" ", "")
        real_root = _root_domain(real)
        if root == real_root:
            return None
        if norm == brand_key and label != brand_key:
            return brand
        if len(brand_key) >= 5 and 0 < _levenshtein(norm, brand_key) <= 1:
            return brand
        # brand name embedded in a different domain: paypal-secure-login.com
        norm_host = host.replace("0", "o").replace("1", "l")
        if (brand_key in host or brand_key in norm_host) and root != real_root:
            return brand
    return None


# --------------------------------------------------------------------------
# Analysis
# --------------------------------------------------------------------------

def _scan_patterns(report: Report, text: str, patterns, category: str, label: str):
    per_hit, cap = WEIGHTS[category]
    total = 0
    seen = set()
    for pat in patterns:
        for m in re.finditer(pat, text, re.I | re.S):
            snippet = " ".join(m.group(0).split())
            key = snippet.lower()
            if key in seen or total >= cap:
                continue
            seen.add(key)
            pts = min(per_hit, cap - total)
            total += pts
            report.add(category, label, pts, snippet)


def analyze_links(report: Report, pe: ParsedEmail, trusted: set[str]):
    urls: dict[str, str] = {}  # url -> visible text ('' if plain)
    for m in URL_RE.finditer(pe.body_text):
        urls.setdefault(m.group(1).rstrip(".,;:!?"), "")
    for href, text in pe.html_links:
        if href and not href.lower().startswith(("mailto:", "tel:", "#")):
            urls[href] = text
    report.links = list(urls)

    for url, shown in urls.items():
        host = _host(url)
        if not host:
            continue
        if _is_trusted(host, trusted):
            continue

        flagged = False

        def flag(desc, pts):
            nonlocal flagged
            flagged = True
            report.add("link", desc, pts, url)

        if IP_HOST_RE.match(host):
            flag("Link points to a raw IP address", 20)
        if host in URL_SHORTENERS:
            flag("Shortened URL hides the real destination", 10)
        if host.startswith("xn--") or ".xn--" in host:
            flag("Punycode domain (possible look-alike characters)", 18)
        if re.match(r"(?i)^https?://[^/]*@", url):
            flag("URL contains '@' (hides the true host)", 18)
        tld = host.rsplit(".", 1)[-1]
        if tld in SUSPICIOUS_TLDS:
            flag(f"Domain uses a commonly abused TLD (.{tld})", 8)
        if host.count(".") >= 4:
            flag("Excessive subdomains", 8)
        if url.lower().startswith("http://"):
            flag("Link is not encrypted (http)", 5)
        brand = _lookalike_brand(host)
        if brand:
            flag(f"Domain imitates the brand '{brand}'", 22)

        # Mismatch between visible text and real target
        if shown:
            shown_urls = URL_RE.findall(shown)
            if shown_urls:
                shown_root = _root_domain(_host(shown_urls[0]))
                if shown_root and shown_root != _root_domain(host):
                    report.add("link", "Link text shows a different site than the real destination",
                               25, f"shows '{shown[:40]}' -> {url}")
                    flagged = True

        known_real = {_root_domain(d) for d in KNOWN_BRANDS.values()}
        if not flagged and _root_domain(host) not in known_real:
            report.add("link", "Link to unrecognised domain", 4, url)


def analyze_sender(report: Report, pe: ParsedEmail, trusted: set[str]):
    from_dom = _domain_of(pe.sender)
    reply_dom = _domain_of(pe.reply_to)

    if reply_dom and from_dom and _root_domain(reply_dom) != _root_domain(from_dom):
        report.add("sender", "Reply-To domain differs from sender domain", 15,
                   f"From {from_dom} / Reply-To {reply_dom}")

    name = _display_name(pe.sender)
    for brand, real in KNOWN_BRANDS.items():
        if brand in name and from_dom and _root_domain(from_dom) != _root_domain(real) \
                and from_dom not in trusted and _root_domain(from_dom) not in trusted:
            report.add("sender", f"Display name claims '{brand}' but email comes from {from_dom}", 25,
                       pe.sender)
            break

    # Display name contains an email address that differs from the real one
    m = EMAIL_ADDR_RE.search(name)
    if m and from_dom and _root_domain(m.group(1)) != _root_domain(from_dom):
        report.add("sender", "Display name contains a different email address", 20, pe.sender)

    if from_dom:
        b = _lookalike_brand(from_dom)
        if b:
            report.add("sender", f"Sender domain imitates the brand '{b}'", 22, from_dom)
        if from_dom.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
            report.add("sender", "Sender domain uses a commonly abused TLD", 6, from_dom)


def analyze_attachments(report: Report, pe: ParsedEmail):
    for name in pe.attachments:
        lower = name.lower()
        ext = "." + lower.rsplit(".", 1)[-1] if "." in lower else ""
        double = re.search(r"\.(pdf|docx?|xlsx?|jpg|png|txt)\.(exe|scr|js|bat|vbs|com|lnk)$", lower)
        if double:
            report.add("attachment", "Double file extension disguises executable", 30, name)
        elif ext in RISKY_EXTENSIONS:
            report.add("attachment", f"Potentially dangerous attachment type ({ext})", 25, name)
        elif ext in ARCHIVE_EXTENSIONS:
            report.add("attachment", "Compressed archive (may hide malware)", 8, name)


def analyze_style(report: Report, pe: ParsedEmail):
    subject = pe.subject
    letters = [c for c in subject if c.isalpha()]
    caps = sum(c.isupper() for c in letters) / len(letters) if letters else 0
    if (len(letters) >= 8 and caps > 0.7) or subject.count("!") >= 2 or pe.body_text.count("!!") >= 1:
        report.add("caps_exclaim", "Shouting style (excess capitals / exclamation marks)",
                   WEIGHTS["caps_exclaim"][0], subject)


def analyze(raw: str | bytes, trusted_domains: set[str] | None = None) -> Report:
    trusted = {d.lower() for d in (trusted_domains or set())}
    pe = parse_email(raw)
    report = Report()
    text = f"{pe.subject}\n{pe.body_text}"

    _scan_patterns(report, text, URGENCY_PATTERNS, "urgency", "Urgency / pressure language")
    _scan_patterns(report, text, SENSITIVE_PATTERNS, "sensitive", "Requests sensitive information")
    _scan_patterns(report, text, LURE_PATTERNS, "lure", "Prize / reward lure")
    _scan_patterns(report, text, THREAT_PATTERNS, "threat", "Threatening language")
    for pat in GENERIC_GREETINGS:
        if re.search(pat, pe.body_text, re.I | re.M):
            report.add("greeting", "Generic greeting (not addressed to you by name)",
                       WEIGHTS["greeting"][0])
            break

    analyze_links(report, pe, trusted)
    analyze_sender(report, pe, trusted)
    analyze_attachments(report, pe)
    analyze_style(report, pe)

    # Combination bonus: classic phishing = urgency + sensitive ask + link
    cats = {f.category for f in report.findings}
    if {"urgency", "sensitive", "link"} <= cats:
        report.add("combo", "Urgency + sensitive-data request + link: classic phishing pattern", 15)

    report.score = min(100, sum(f.points for f in report.findings))
    report.level = next(label for floor, label in RISK_LEVELS if report.score >= floor)
    return report


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

ICONS = {"HIGH": "[!!!]", "MEDIUM": "[!!]", "LOW": "[!]", "SAFE": "[ok]"}
ADVICE = {
    "HIGH": "Do NOT click links, open attachments, or reply. Report as phishing and delete.",
    "MEDIUM": "Be cautious. Verify the sender through a separate channel before acting.",
    "LOW": "Minor warning signs. Double-check anything that asks you to act.",
    "SAFE": "No significant risk indicators found (this is not a guarantee of safety).",
}


def format_report(report: Report, title: str = "") -> str:
    bar_len = 30
    filled = round(report.score / 100 * bar_len)
    bar = "#" * filled + "-" * (bar_len - filled)
    lines = []
    if title:
        lines.append(f"=== {title} ===")
    lines.append(f"{ICONS[report.level]} Risk level: {report.level}   Score: {report.score}/100")
    lines.append(f"    [{bar}]")
    if report.findings:
        lines.append("\nFindings:")
        for f in sorted(report.findings, key=lambda x: -x.points):
            ev = f"  -> {f.evidence}" if f.evidence else ""
            lines.append(f"  +{f.points:<3} [{f.category}] {f.description}{ev}")
    if report.links:
        lines.append(f"\nLinks found: {len(report.links)}")
        for l in report.links[:10]:
            lines.append(f"  - {l}")
    lines.append(f"\nAdvice: {ADVICE[report.level]}")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Demo data
# --------------------------------------------------------------------------

DEMO_EMAILS = {
    "Phishing: fake bank alert": """From: "SBI Security" <alert@sbi-secure-verify.xyz>
Reply-To: helpdesk@gmail-support.top
Subject: URGENT!! Your account will be suspended

Dear Customer,

We detected unauthorized access to your account. You must verify your
account immediately within 24 hours or your account will be suspended.
Please confirm your password and OTP at: http://192.168.4.7/sbi/login
or http://bit.ly/3xYzAbc

Failure to comply will result in legal action.
""",
    "Phishing: HTML link mismatch + lottery": """From: PayPal Support <noreply@paypa1-billing.com>
Subject: Congratulations! You have won a prize
Content-Type: text/html

<html><body>
<p>Hello user, claim your reward now. Provide your credit card number to receive funds.</p>
<a href="http://paypa1-billing.com/claim">https://www.paypal.com/claim</a>
</body></html>
""",
    "Legitimate: team meeting": """From: Priya Sharma <priya@mycompany.com>
Subject: Notes from Tuesday's meeting

Hi Alex,

Attached are the notes from our planning meeting. Let's review the
roadmap at https://mycompany.com/wiki/roadmap before Thursday.

Thanks,
Priya
""",
}


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Scan emails for phishing / unsafe content.")
    ap.add_argument("files", nargs="*", help="Email files (.eml / .txt), or '-' for stdin")
    ap.add_argument("--demo", action="store_true", help="Run built-in sample emails")
    ap.add_argument("--json", action="store_true", help="Output JSON")
    ap.add_argument("--trusted", nargs="*", default=[], metavar="DOMAIN",
                    help="Domains to treat as trusted (e.g. your company)")
    args = ap.parse_args(argv)

    trusted = set(args.trusted)
    if args.demo:
        trusted.add("mycompany.com")
    jobs: list[tuple[str, str | bytes]] = []

    if args.demo:
        jobs += list(DEMO_EMAILS.items())
    for f in args.files:
        if f == "-":
            jobs.append(("stdin", sys.stdin.read()))
        else:
            with open(f, "rb") as fh:
                jobs.append((f, fh.read()))

    if not jobs:
        ap.print_help()
        return 2

    worst = 0
    outputs = []
    for name, raw in jobs:
        rep = analyze(raw, trusted)
        worst = max(worst, rep.score)
        if args.json:
            outputs.append({"source": name, **asdict(rep)})
        else:
            print(format_report(rep, name), end="\n\n")
    if args.json:
        print(json.dumps(outputs, indent=2))

    # Exit code useful for scripting: 1 if any message is HIGH risk
    return 1 if worst >= 60 else 0


if __name__ == "__main__":
    sys.exit(main())
