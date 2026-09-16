# phishguard

Phishing URL analysis and risk scoring. Scores a link on the signals that
actually separate a phishing URL from a legitimate one, and explains every
point it assigns.

**Defensive tooling** — it analyses links so people do not have to click them.

## Signals

| Signal | Weight | What it catches |
| --- | --- | --- |
| `typosquatting` | 45 / 40 | A brand with digits swapped for letters (`g00gle`, `paypa1`), or within one edit of it (`gogle`) |
| `userinfo-obfuscation` | 35 | `http://real-bank.com@evil.example/` — everything before `@` is ignored by the browser |
| `homoglyph-characters` | 35 | Cyrillic or Greek lookalikes standing in for Latin letters |
| `brand-token-in-domain` | 35 | `paypal-secure-verify.tk` — the brand as one token of an unrelated domain |
| `brand-in-subdomain` | 35 | `paypal.login.secure-update.xyz` — the brand pushed into a subdomain |
| `punycode-domain` | 30 | `xn--` encoded internationalised domains imitating Latin names |
| `ip-address-host` | 30 | A raw IP instead of a domain name |
| `executable-payload` | 30 | Links pointing straight at `.exe`, `.apk`, `.scr`, `.hta`, … |
| `brand-in-domain` | 25 | A brand name embedded in an unrelated domain |
| `redirect-to-other-host` | 18 | The chain ends on a different host than advertised |
| `credential-lure` | 8–16 | `login`, `verify`, `suspended`, `unlock`, `billing` in the path |
| `high-risk-tld` | 15 | `.tk`, `.zip`, `.xyz`, `.top`, `.click`, … |
| `subdomain-stuffing` | 12 | Deep label chains used to hide the real domain |
| `url-shortener` | 12 | The destination is concealed until the link is opened |
| `no-tls` | 10 | Plain HTTP on a page that asks for credentials |
| `hyphen-stuffing` | 10 | Three or more hyphens assembling a brand-like name |

### Verdicts

| Score | Verdict |
| --- | --- |
| 60+ | `malicious` |
| 35–59 | `suspicious` |
| 15–34 | `questionable` |
| 0–14 | `likely benign` |

## Requirements

Python 3.10 or newer. No packages to install.
Network access is only used with `--follow`.

## Usage

```bash
# Analyse one URL in full
python3 phishguard.py 'http://paypa1-secure-verify.tk/login/confirm.php'

# Bulk triage a list, one line of output per URL
python3 phishguard.py -f suspicious-urls.txt -q

# Follow the redirect chain (HEAD requests only — page content is never executed)
python3 phishguard.py 'https://bit.ly/3xAmPle' --follow

# Check against your own organisation's brands
python3 phishguard.py -f urls.txt --brands "acmebank,acme-pay,acmecard"
```

### Options

| Flag | Description | Default |
| --- | --- | --- |
| `-f`, `--file` | Analyse every URL in this file | — |
| `--brands` | Comma-separated brand list to check against | built-in list |
| `--follow` | Follow the redirect chain | off |
| `--timeout` | Request timeout in seconds | `8` |
| `-q`, `--quiet` | One line per URL, for bulk triage | off |
| `-o`, `--output` | Write results as JSON | — |

## Accuracy

Measured against a mixed set of real and crafted URLs:

```
likely benign     0  https://outlook.office365.com/mail/
likely benign     0  https://login.microsoft.com/
likely benign     0  https://www.amazon.co.uk/orders
likely benign     0  https://github.com/torvalds/linux
likely benign     8  https://accounts.google.com/signin
suspicious       51  https://micr0soft-verify.com/account/login
suspicious       53  https://g00gle.com/signin
suspicious       58  https://paypal.login.secure-update.xyz/signin
malicious        76  http://paypa1-secure-verify.tk/login/confirm.php
```

Two false-positive classes are handled explicitly:

- **A brand's own subdomains.** `outlook.office365.com` and `mail.google.com`
  are legitimate, so when the registered domain *is* a watched brand the
  impersonation checks are skipped entirely.
- **Legitimate domains containing digits.** Digit folding is applied only for
  comparison, and the raw label is what decides brand ownership — so
  `office365.com` is never mistaken for a digit-swapped imitation.

## Design notes

- **Nothing is fetched by default.** Analysis is purely structural unless you
  pass `--follow`, and even then only `HEAD` requests are sent — page content
  is never downloaded or executed.
- **Scoring is additive and transparent.** Every signal prints its own weight,
  so a verdict can always be justified to the person who reported the link.
- **The brand list is yours to set.** `--brands` lets a company check its own
  names, which is where this is most useful.

## Limitations

This is a heuristic tool, not a reputation service. It cannot know that a
never-before-seen domain was registered an hour ago, and a well-built phishing
page on a compromised legitimate domain will score low. Use it as one input
alongside threat intelligence and reputation feeds.

## Tests

63 tests, 94% line coverage. No dependencies, and **no test contacts a
real external service** — network-facing code is exercised against local fake
servers bound to an ephemeral port.

```bash
# Run the suite
python3 -m unittest discover -s tests -v

# Fail on any leaked socket, file, or database connection
python3 -W error::ResourceWarning -m unittest discover -s tests
```

CI runs the suite on Python 3.10–3.13 on every push, plus a coverage gate and a
3.10 syntax check. See [.github/workflows/tests.yml](.github/workflows/tests.yml).

## License

MIT — see [LICENSE](LICENSE).
