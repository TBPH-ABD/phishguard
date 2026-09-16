#!/usr/bin/env python3
"""phishguard — phishing URL analysis and risk scoring.

Scores a URL on the signals that actually distinguish a phishing link from a
legitimate one: brand typosquatting, homoglyph and punycode deception,
credential-harvest keywords, host obfuscation, disposable TLDs, and redirect
chains that end somewhere other than where they claimed.

Defensive tooling. It analyses links so people do not have to click them.

Standard library only.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict

# Brands impersonated often enough to be worth checking by default.
WATCHED_BRANDS = [
    "google", "facebook", "instagram", "whatsapp", "apple", "icloud",
    "microsoft", "outlook", "office365", "linkedin", "twitter", "netflix",
    "amazon", "paypal", "binance", "coinbase", "dropbox", "github",
    "steam", "spotify", "telegram", "snapchat", "tiktok", "yahoo",
]

# TLDs disproportionately represented in phishing campaigns because they are
# free or near-free to register.
RISKY_TLDS = {
    "zip", "mov", "tk", "ml", "ga", "cf", "gq", "xyz", "top", "buzz",
    "click", "link", "work", "country", "kim", "loan", "rest", "quest",
    "cam", "surf", "cfd", "sbs", "icu",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rb.gy", "shorturl.at", "rebrand.ly", "t.ly", "short.io",
}

# Words that appear in the path of credential-harvesting pages.
LURE_WORDS = [
    "login", "signin", "verify", "verification", "account", "secure",
    "update", "confirm", "password", "banking", "wallet", "suspended",
    "unlock", "recover", "billing", "invoice", "authenticate", "validate",
]

# Latin lookalikes from other scripts, the core of a homoglyph attack.
HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "ѕ": "s", "і": "i", "ј": "j", "ԁ": "d", "ɡ": "g", "ʟ": "l", "ᴏ": "o",
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "ϲ": "c", "ԛ": "q", "ｅ": "e",
}

IP_HOST = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

# Digit-for-letter swaps: paypa1.com, g00gle.com, micr0soft.com.
DIGIT_SWAPS = str.maketrans({"1": "l", "0": "o", "3": "e", "5": "s",
                             "4": "a", "7": "t", "8": "b"})


@dataclass
class Signal:
    weight: int
    label: str
    detail: str


@dataclass
class Analysis:
    url: str
    host: str = ""
    score: int = 0
    verdict: str = "unknown"
    signals: list[Signal] = field(default_factory=list)
    redirect_chain: list[str] = field(default_factory=list)

    def add(self, weight: int, label: str, detail: str) -> None:
        self.signals.append(Signal(weight, label, detail))
        self.score += weight


def levenshtein(a: str, b: str) -> int:
    """Edit distance, used to catch a brand name that is one typo away."""
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1,        # deletion
                               current[j - 1] + 1,     # insertion
                               previous[j - 1] + (ca != cb)))  # substitution
        previous = current
    return previous[-1]


def normalise_homoglyphs(text: str) -> tuple[str, list[str]]:
    """Fold lookalike characters to Latin. Returns (folded, characters found)."""
    found = []
    out = []
    for char in text:
        if char in HOMOGLYPHS:
            found.append(f"{char!r} ({unicodedata.name(char, 'unknown')})")
            out.append(HOMOGLYPHS[char])
        else:
            out.append(char)
    return "".join(out), found


def registered_domain(host: str) -> tuple[str, str]:
    """Crude eTLD+1 split. Returns (domain_label, tld)."""
    parts = host.split(".")
    if len(parts) < 2:
        return host, ""
    # Handle the common two-level public suffixes without a full PSL.
    two_level = {"co.uk", "com.au", "co.jp", "com.br", "co.in", "com.sa",
                 "com.ye", "co.za", "com.tr", "org.uk", "net.au", "gov.uk"}
    if len(parts) >= 3 and ".".join(parts[-2:]) in two_level:
        return parts[-3], ".".join(parts[-2:])
    return parts[-2], parts[-1]


def analyse(url: str, brands: list[str], follow: bool,
            timeout: float) -> Analysis:
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url

    result = Analysis(url=url)
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").lower()
    result.host = host

    if not host:
        result.add(40, "unparseable", "The URL has no resolvable host component.")
        result.verdict = verdict_for(result.score)
        return result

    # --- Transport ---------------------------------------------------------
    if parsed.scheme != "https":
        result.add(10, "no-tls",
                   "Served over plain HTTP. Credentials entered here travel "
                   "in cleartext.")

    # --- Host obfuscation --------------------------------------------------
    if IP_HOST.match(host):
        result.add(30, "ip-address-host",
                   "The host is a raw IP address rather than a domain name — "
                   "legitimate brands do not do this.")

    if "@" in parsed.netloc:
        result.add(35, "userinfo-obfuscation",
                   "The URL contains '@'. Everything before it is ignored by "
                   "the browser, so the real destination is hidden.")

    if parsed.port and parsed.port not in (80, 443):
        result.add(10, "nonstandard-port",
                   f"Connects on port {parsed.port} instead of 80 or 443.")

    labels = host.split(".")
    if len(labels) > 4:
        result.add(12, "subdomain-stuffing",
                   f"{len(labels)} labels deep. Deep subdomain chains are used "
                   f"to push a brand name into a URL that does not belong to it.")

    if host.count("-") >= 3:
        result.add(10, "hyphen-stuffing",
                   f"{host.count('-')} hyphens in the host — a common way to "
                   f"assemble a brand-like name.")

    if len(url) > 100:
        result.add(6, "excessive-length",
                   f"{len(url)} characters. Long URLs hide the real destination "
                   f"in address bars and message previews.")

    # --- Punycode and homoglyphs -------------------------------------------
    if "xn--" in host:
        try:
            decoded = host.encode("ascii").decode("idna")
        except (UnicodeError, UnicodeDecodeError):
            decoded = host
        result.add(30, "punycode-domain",
                   f"Internationalised domain encoded as punycode. It renders "
                   f"as '{decoded}', which may imitate a Latin brand name.")

    folded_host, glyphs = normalise_homoglyphs(host)
    if glyphs:
        result.add(35, "homoglyph-characters",
                   f"Contains lookalike characters from another script: "
                   f"{', '.join(glyphs[:4])}.")

    # --- Brand impersonation ------------------------------------------------
    domain_label, tld = registered_domain(folded_host)
    subdomain_part = ".".join(folded_host.split(".")[:-2]) if len(labels) > 2 else ""

    # Fold digit-for-letter swaps before comparing, so paypa1 reads as paypal.
    deleeted = domain_label.translate(DIGIT_SWAPS)
    # A brand is often one token of a hyphenated name: paypal-secure-verify.
    tokens = [t for t in re.split(r"[-_]", deleeted) if t]

    # If the registered domain is itself a watched brand, the brand appearing
    # in a subdomain is expected, not impersonation: outlook.office365.com and
    # mail.google.com are both legitimate. Skip the impersonation checks.
    # Compare the RAW label here, not the digit-folded one: office365 is a real
    # Microsoft domain, and folding its digits would stop it matching.
    brand_owns_domain = domain_label in brands

    for brand in [] if brand_owns_domain else brands:
        if domain_label == brand:
            break  # the real thing, or at least the real label

        # Digit-swapped but otherwise identical: g00gle, micr0soft, paypa1.
        if deleeted == brand:
            result.add(45, "typosquatting",
                       f"Domain '{domain_label}' is the brand '{brand}' with "
                       f"digits substituted for letters — a deliberate visual "
                       f"imitation.")
            break

        # Whole-label typo, e.g. gogle / payapl.
        distance = levenshtein(deleeted, brand)
        if 0 < distance <= max(1, len(brand) // 5):
            swapped = " (after folding digit substitutions)" \
                if deleeted != domain_label else ""
            result.add(40, "typosquatting",
                       f"Registered domain '{domain_label}' is {distance} "
                       f"edit(s) from the brand '{brand}'{swapped}.")
            break

        # One token of a hyphenated name is the brand, or a typo of it.
        token_hit = next(
            (t for t in tokens
             if t == brand or levenshtein(t, brand) <= max(1, len(brand) // 5)),
            None)
        if token_hit and len(tokens) > 1:
            result.add(35, "brand-token-in-domain",
                       f"'{token_hit}' in the domain '{domain_label}' imitates "
                       f"the brand '{brand}', but the registered domain is not "
                       f"the brand's.")
            break

        if brand in subdomain_part:
            result.add(35, "brand-in-subdomain",
                       f"'{brand}' appears in the subdomain of '{domain_label}"
                       f".{tld}', which is not the brand's domain.")
            break
        if brand in deleeted and deleeted != brand:
            result.add(25, "brand-in-domain",
                       f"'{brand}' is embedded in the unrelated domain "
                       f"'{domain_label}'.")
            break

    # --- TLD and shorteners -------------------------------------------------
    if tld.split(".")[-1] in RISKY_TLDS:
        result.add(15, "high-risk-tld",
                   f"'.{tld}' is heavily over-represented in phishing because "
                   f"registration is free or near-free.")

    if host in SHORTENERS or folded_host in SHORTENERS:
        result.add(12, "url-shortener",
                   "A link shortener conceals the true destination until the "
                   "moment it is opened.")

    # --- Path lures ----------------------------------------------------------
    path_and_query = (parsed.path + "?" + parsed.query).lower()
    hits = [word for word in LURE_WORDS if word in path_and_query]
    if hits:
        weight = 8 if len(hits) == 1 else 16
        result.add(weight, "credential-lure",
                   f"Path contains credential-harvest wording: "
                   f"{', '.join(hits[:5])}.")

    if re.search(r"\.(exe|scr|bat|cmd|apk|jar|vbs|ps1|hta)($|\?)",
                 path_and_query):
        result.add(30, "executable-payload",
                   "The URL points directly at an executable file type.")

    # --- Redirect chain (opt-in, network) ------------------------------------
    if follow:
        chain = trace_redirects(url, timeout)
        result.redirect_chain = chain
        if len(chain) > 1:
            final_host = (urllib.parse.urlparse(chain[-1]).hostname or "").lower()
            if final_host and final_host != host:
                result.add(18, "redirect-to-other-host",
                           f"Redirects to a different host: '{final_host}'.")
        if len(chain) > 3:
            result.add(10, "long-redirect-chain",
                       f"{len(chain)} hops before the final destination.")

    result.verdict = verdict_for(result.score)
    return result


def trace_redirects(url: str, timeout: float, max_hops: int = 6) -> list[str]:
    """Follow redirects without ever executing page content."""
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None

    opener = urllib.request.build_opener(NoRedirect)
    chain = [url]
    current = url
    for _ in range(max_hops):
        request = urllib.request.Request(
            current, method="HEAD",
            headers={"User-Agent": "phishguard/1.0 (link safety check)"})
        try:
            with opener.open(request, timeout=timeout):
                break  # a non-redirect response ends the chain
        except urllib.error.HTTPError as exc:
            location = exc.headers.get("Location") if exc.headers else None
            if exc.code in (301, 302, 303, 307, 308) and location:
                current = urllib.parse.urljoin(current, location)
                chain.append(current)
                continue
            break
        except (urllib.error.URLError, OSError, ValueError):
            break
    return chain


def verdict_for(score: int) -> str:
    if score >= 60:
        return "malicious"
    if score >= 35:
        return "suspicious"
    if score >= 15:
        return "questionable"
    return "likely benign"


def print_analysis(analysis: Analysis, quiet: bool) -> None:
    if quiet:
        print(f"{analysis.verdict:<15} {analysis.score:>3}  {analysis.url}")
        return

    print(f"\n  URL      : {analysis.url}")
    print(f"  Host     : {analysis.host}")
    print(f"  Score    : {analysis.score}")
    print(f"  Verdict  : {analysis.verdict.upper()}")

    if analysis.redirect_chain and len(analysis.redirect_chain) > 1:
        print(f"  Redirects:")
        for hop in analysis.redirect_chain:
            print(f"      -> {hop}")

    if analysis.signals:
        print(f"\n  Signals ({len(analysis.signals)}):")
        for signal in sorted(analysis.signals, key=lambda s: -s.weight):
            print(f"    +{signal.weight:<3} {signal.label}")
            print(f"         {signal.detail}")
    else:
        print("\n  No phishing signals detected.")
    print()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Phishing URL analysis and risk scoring.")
    parser.add_argument("url", nargs="?", help="URL to analyse")
    parser.add_argument("-f", "--file", help="analyse every URL in this file")
    parser.add_argument("--brands",
                        help="comma-separated brand list to check against "
                             "(defaults to a built-in list)")
    parser.add_argument("--follow", action="store_true",
                        help="follow the redirect chain (makes HEAD requests)")
    parser.add_argument("--timeout", type=float, default=8.0,
                        help="request timeout in seconds (default 8)")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="one line per URL, for bulk triage")
    parser.add_argument("-o", "--output", help="write results as JSON")
    args = parser.parse_args(argv)

    brands = [b.strip().lower() for b in args.brands.split(",")] \
        if args.brands else WATCHED_BRANDS

    urls: list[str] = []
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
                urls = [line.strip() for line in fh
                        if line.strip() and not line.startswith("#")]
        except OSError as exc:
            print(f"Could not read {args.file}: {exc}", file=sys.stderr)
            return 2
    elif args.url:
        urls = [args.url]
    else:
        parser.error("supply a URL or --file")

    results = [analyse(url, brands, args.follow, args.timeout) for url in urls]
    for analysis in results:
        print_analysis(analysis, args.quiet)

    if args.file and not args.quiet:
        flagged = sum(1 for r in results
                      if r.verdict in ("malicious", "suspicious"))
        print(f"  {len(results)} analysed, {flagged} flagged.\n")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump([asdict(r) for r in results], fh, indent=2)
        print(f"  Written to {args.output}\n")

    return 1 if any(r.verdict in ("malicious", "suspicious")
                    for r in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
