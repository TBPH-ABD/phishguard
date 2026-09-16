"""Tests for phishguard URL analysis and scoring."""
from __future__ import annotations

import json
import os
import tempfile
import unittest

import phishguard
from tests.support.fakes import capture_cli, http_fake
from phishguard import (WATCHED_BRANDS, analyse, levenshtein,
                        normalise_homoglyphs, registered_domain, verdict_for)


def score(url: str, follow: bool = False) -> phishguard.Analysis:
    return analyse(url, WATCHED_BRANDS, follow, timeout=1.0)


def labels(result: phishguard.Analysis) -> set[str]:
    return {signal.label for signal in result.signals}


class TestLevenshtein(unittest.TestCase):
    def test_identical_strings_are_zero(self):
        self.assertEqual(levenshtein("google", "google"), 0)

    def test_single_substitution(self):
        self.assertEqual(levenshtein("google", "goggle"), 1)

    def test_single_deletion(self):
        self.assertEqual(levenshtein("google", "gogle"), 1)

    def test_is_symmetric(self):
        self.assertEqual(levenshtein("paypal", "papyal"),
                         levenshtein("papyal", "paypal"))

    def test_empty_string_equals_length(self):
        self.assertEqual(levenshtein("", "abcd"), 4)


class TestHomoglyphs(unittest.TestCase):
    def test_cyrillic_a_is_folded_to_latin(self):
        folded, found = normalise_homoglyphs("pаypal")
        self.assertEqual(folded, "paypal")
        self.assertEqual(len(found), 1)

    def test_plain_ascii_is_untouched(self):
        folded, found = normalise_homoglyphs("paypal")
        self.assertEqual(folded, "paypal")
        self.assertEqual(found, [])


class TestRegisteredDomain(unittest.TestCase):
    def test_simple_domain(self):
        self.assertEqual(registered_domain("example.com"), ("example", "com"))

    def test_strips_subdomains(self):
        self.assertEqual(registered_domain("mail.google.com"),
                         ("google", "com"))

    def test_handles_two_level_public_suffix(self):
        self.assertEqual(registered_domain("www.amazon.co.uk"),
                         ("amazon", "co.uk"))


class TestVerdict(unittest.TestCase):
    def test_thresholds(self):
        self.assertEqual(verdict_for(0), "likely benign")
        self.assertEqual(verdict_for(14), "likely benign")
        self.assertEqual(verdict_for(15), "questionable")
        self.assertEqual(verdict_for(35), "suspicious")
        self.assertEqual(verdict_for(60), "malicious")
        self.assertEqual(verdict_for(999), "malicious")


class TestLegitimateUrls(unittest.TestCase):
    """Legitimate URLs must not be flagged. False positives destroy trust."""

    def test_plain_brand_domain_scores_zero(self):
        self.assertEqual(score("https://www.google.com/search?q=hi").score, 0)

    def test_brand_subdomain_of_own_domain_is_clean(self):
        # mail.google.com is Google's own — not impersonation.
        result = score("https://mail.google.com/mail/u/0")
        self.assertEqual(result.score, 0)
        self.assertNotIn("brand-in-subdomain", labels(result))

    def test_brand_owning_a_digit_domain_is_clean(self):
        # office365.com is a real Microsoft domain; digit folding must not
        # turn it into a suspected imitation.
        result = score("https://outlook.office365.com/mail/")
        self.assertEqual(result.score, 0)
        self.assertNotIn("typosquatting", labels(result))

    def test_two_level_suffix_domain_is_clean(self):
        self.assertEqual(score("https://www.amazon.co.uk/orders").score, 0)

    def test_unrelated_domain_is_clean(self):
        self.assertEqual(score("https://github.com/torvalds/linux").score, 0)

    def test_login_path_alone_stays_benign(self):
        # A credential keyword on a legitimate domain is weak evidence only.
        result = score("https://accounts.google.com/signin")
        self.assertEqual(result.verdict, "likely benign")


class TestTyposquatting(unittest.TestCase):
    def test_digit_substitution_is_detected(self):
        result = score("https://g00gle.com/signin")
        self.assertIn("typosquatting", labels(result))
        self.assertEqual(result.verdict, "suspicious")

    def test_single_edit_typo_is_detected(self):
        self.assertIn("typosquatting", labels(score("https://gogle.com/")))

    def test_brand_as_token_of_hyphenated_domain(self):
        result = score("https://micr0soft-verify.com/account/login")
        self.assertIn("brand-token-in-domain", labels(result))

    def test_brand_pushed_into_subdomain(self):
        result = score("https://paypal.login.secure-update.xyz/signin")
        self.assertIn("brand-in-subdomain", labels(result))
        self.assertEqual(result.verdict, "suspicious")


class TestHostObfuscation(unittest.TestCase):
    def test_userinfo_at_sign_is_flagged(self):
        result = score("http://192.168.1.1@evil.example.com/account/verify")
        self.assertIn("userinfo-obfuscation", labels(result))

    def test_raw_ip_host_is_flagged(self):
        self.assertIn("ip-address-host", labels(score("http://93.184.216.34/login")))

    def test_punycode_is_flagged(self):
        self.assertIn("punycode-domain",
                      labels(score("http://xn--80ak6aa92e.com/verify")))

    def test_deep_subdomain_chain_is_flagged(self):
        result = score("http://a.b.c.d.e.example.com/")
        self.assertIn("subdomain-stuffing", labels(result))

    def test_nonstandard_port_is_flagged(self):
        self.assertIn("nonstandard-port", labels(score("http://example.com:8081/")))


class TestPathSignals(unittest.TestCase):
    def test_single_lure_word_scores_less_than_several(self):
        one = score("http://example.com/login")
        many = score("http://example.com/login/verify/account")
        self.assertLess(one.score, many.score)

    def test_executable_target_is_flagged(self):
        self.assertIn("executable-payload",
                      labels(score("http://example.com/update.exe")))

    def test_plain_http_is_flagged(self):
        self.assertIn("no-tls", labels(score("http://example.com/")))

    def test_https_is_not_flagged_for_tls(self):
        self.assertNotIn("no-tls", labels(score("https://example.com/")))


class TestCombinedScoring(unittest.TestCase):
    def test_full_phishing_url_is_malicious(self):
        result = score("http://paypa1-secure-verify.tk/login/confirm.php")
        self.assertEqual(result.verdict, "malicious")
        self.assertIn("high-risk-tld", labels(result))
        self.assertIn("credential-lure", labels(result))

    def test_score_is_the_sum_of_signal_weights(self):
        result = score("http://paypa1-secure-verify.tk/login/confirm.php")
        self.assertEqual(result.score,
                         sum(s.weight for s in result.signals))

    def test_custom_brand_list_is_honoured(self):
        result = analyse("https://acmebank-login.xyz/verify",
                         ["acmebank"], False, 1.0)
        self.assertIn("brand-token-in-domain", labels(result))

    def test_scheme_is_added_when_missing(self):
        self.assertTrue(score("example.com/path").url.startswith("http://"))

    def test_unparseable_url_is_handled(self):
        result = score("http:///nohost")
        self.assertIn("unparseable", labels(result))


class TestCli(unittest.TestCase):
    def test_exits_nonzero_for_phishing_url(self):
        code, out = capture_cli(
            phishguard.main, ["http://paypa1-secure-verify.tk/login", "-q"])
        self.assertEqual(code, 1)
        self.assertIn("malicious", out)

    def test_exits_zero_for_benign_url(self):
        code, out = capture_cli(phishguard.main, ["https://github.com/x", "-q"])
        self.assertEqual(code, 0)
        self.assertIn("likely benign", out)


if __name__ == "__main__":
    unittest.main()


class TestRedirectChain(unittest.TestCase):
    """--follow is the only part of phishguard that touches the network."""

    def test_single_hop_chain_when_no_redirect(self):
        with http_fake({"/": (200, {}, "ok")}) as (base, _):
            chain = phishguard.trace_redirects(base + "/", timeout=5.0)
        self.assertEqual(len(chain), 1)

    def test_redirect_is_followed_and_recorded(self):
        routes = {"/start": (302, {"Location": "/end"}, ""),
                  "/end": (200, {}, "ok")}
        with http_fake(routes) as (base, _):
            chain = phishguard.trace_redirects(base + "/start", timeout=5.0)
        self.assertEqual(len(chain), 2)
        self.assertTrue(chain[-1].endswith("/end"))

    def test_chain_stops_at_the_hop_limit(self):
        # A route that redirects to itself would loop forever without a cap.
        routes = {"/loop": (302, {"Location": "/loop"}, "")}
        with http_fake(routes) as (base, _):
            chain = phishguard.trace_redirects(base + "/loop", timeout=5.0,
                                               max_hops=3)
        self.assertLessEqual(len(chain), 4)

    def test_unreachable_host_returns_the_original_url(self):
        chain = phishguard.trace_redirects("http://127.0.0.1:1/x", timeout=1.0)
        self.assertEqual(chain, ["http://127.0.0.1:1/x"])

    def test_only_head_requests_are_sent(self):
        """Page content must never be downloaded, let alone executed."""
        with http_fake({"/": (200, {}, "ok")}) as (base, recorder):
            phishguard.trace_redirects(base + "/", timeout=5.0)
        self.assertEqual({r["method"] for r in recorder.requests}, {"HEAD"})

    def test_redirect_to_another_host_is_scored(self):
        with http_fake({"/a": (200, {}, "ok")}) as (other, _):
            # Redirect to "localhost" rather than the fake's own 127.0.0.1 so
            # the hostnames genuinely differ; the tool compares host, not port.
            elsewhere = other.replace("127.0.0.1", "localhost") + "/a"
            with http_fake({"/go": (302, {"Location": elsewhere}, "")}) \
                    as (base, _):
                result = analyse(base + "/go", WATCHED_BRANDS, True, 5.0)
        self.assertIn("redirect-to-other-host", labels(result))

    def test_long_chain_is_scored(self):
        routes = {f"/h{i}": (302, {"Location": f"/h{i + 1}"}, "")
                  for i in range(5)}
        routes["/h5"] = (200, {}, "ok")
        with http_fake(routes) as (base, _):
            result = analyse(base + "/h0", WATCHED_BRANDS, True, 5.0)
        self.assertIn("long-redirect-chain", labels(result))


class TestOutputAndCliOptions(unittest.TestCase):
    def test_verbose_output_lists_signals(self):
        _, out = capture_cli(phishguard.main,
                             ["http://paypa1-secure-verify.tk/login"])
        self.assertIn("Signals", out)
        self.assertIn("high-risk-tld", out)
        self.assertIn("MALICIOUS", out)

    def test_clean_url_reports_no_signals(self):
        _, out = capture_cli(phishguard.main, ["https://github.com/torvalds"])
        self.assertIn("No phishing signals detected", out)

    def test_file_mode_analyses_every_url(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "urls.txt")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("# a comment line\n"
                         "https://github.com/x\n"
                         "\n"
                         "http://paypa1-secure-verify.tk/login\n")
            code, out = capture_cli(phishguard.main, ["-f", path])
        self.assertEqual(code, 1)
        self.assertIn("2 analysed, 1 flagged", out)

    def test_custom_brand_list_via_cli(self):
        _, out = capture_cli(phishguard.main,
                             ["https://acmebank-verify.xyz/login",
                              "--brands", "acmebank,acmepay"])
        self.assertIn("acmebank", out)

    def test_json_output_is_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_file = os.path.join(tmp, "r.json")
            capture_cli(phishguard.main,
                        ["http://paypa1-secure-verify.tk/login", "-q",
                         "-o", out_file])
            with open(out_file, encoding="utf-8") as fh:
                data = json.load(fh)
        self.assertEqual(data[0]["verdict"], "malicious")
        self.assertTrue(data[0]["signals"])

    def test_missing_file_reports_error(self):
        code, out = capture_cli(phishguard.main, ["-f", "/nope/urls.txt"])
        self.assertEqual(code, 2)
        self.assertIn("Could not read", out)

    def test_no_argument_is_rejected(self):
        with self.assertRaises(SystemExit):
            capture_cli(phishguard.main, [])
