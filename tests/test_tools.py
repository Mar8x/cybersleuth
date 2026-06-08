"""
CyberSleuth test battery — three tiers:
  1. Structural  — imports, __all__, server syntax, doc files on disk
  2. Pure logic  — regex/classification functions, no network
  3. Mocked HTTP — full tool functions with requests.get/post mocked
"""
import ast
import datetime
import json
import re
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

# Make sure project root is on sys.path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


# ---------------------------------------------------------------------------
# Tier 1: Structural
# ---------------------------------------------------------------------------

class TestStructural:
    def test_tools_syntax(self):
        src = (ROOT / "tools.py").read_text()
        ast.parse(src)

    def test_server_syntax(self):
        src = (ROOT / "server.py").read_text()
        ast.parse(src)

    def test_all_exports_importable(self):
        import tools
        for name in tools.__all__:
            assert hasattr(tools, name), f"tools.__all__ entry '{name}' not found in module"
            assert callable(getattr(tools, name)), f"'{name}' is not callable"

    def test_all_count(self):
        import tools
        assert len(tools.__all__) >= 21, "Expected at least 21 exports"

    def test_doc_files_exist(self):
        docs = [
            "docs/privacy-analysis.md",
            "docs/llm-recon.md",
            "docs/tech-stack-recon.md",
            "docs/domain-workflow.md",
            "cybersleuth.md",
            "reports.md",
            "people-osint.md",
        ]
        for doc in docs:
            assert (ROOT / doc).exists(), f"Missing: {doc}"

    def test_new_tools_in_all(self):
        import tools
        for name in ["get_privacy_policy", "scan_trackers",
                     "find_career_sources", "fetch_job_postings",
                     "github_org_recon", "tech_stack_profile",
                     "llm_fingerprint", "llm_probe_public_chat", "llm_security_probe"]:
            assert name in tools.__all__, f"'{name}' missing from __all__"


# ---------------------------------------------------------------------------
# Tier 2: Pure logic — privacy analysis
# ---------------------------------------------------------------------------

class TestPrivacyDetectJurisdictions:
    def setup_method(self):
        from tools import _detect_jurisdictions
        self.fn = _detect_jurisdictions

    def test_gdpr_detected(self):
        text = "We comply with the GDPR. You have the right to access your data."
        result = self.fn(text)
        ids = [j["id"] for j in result]
        assert "gdpr" in ids

    def test_ccpa_detected(self):
        text = "California residents have rights under CCPA. Do Not Sell or Share."
        result = self.fn(text)
        ids = [j["id"] for j in result]
        assert "ccpa_cpra" in ids

    def test_both_detected(self):
        text = "GDPR applies to EU users. CCPA applies to California residents."
        result = self.fn(text)
        ids = [j["id"] for j in result]
        assert "gdpr" in ids
        assert "ccpa_cpra" in ids

    def test_lgpd_detected(self):
        text = "Nos termos da LGPD (Lei Geral de Proteção de Dados), você tem direitos."
        result = self.fn(text)
        ids = [j["id"] for j in result]
        assert "lgpd" in ids

    def test_none_detected_for_generic_text(self):
        text = "We use cookies to improve your experience on our website."
        result = self.fn(text)
        assert result == []

    def test_result_structure(self):
        result = self.fn("This policy complies with GDPR.")
        assert result
        for j in result:
            assert "id" in j
            assert "name" in j
            assert "regions" in j


class TestPracticeCategories:
    def setup_method(self):
        from tools import _detect_practice_categories
        self.fn = _detect_practice_categories

    def test_data_collection_detected(self):
        text = "We collect your email address and name when you sign up."
        result = self.fn(text)
        assert result["data_collection"] is True

    def test_data_sharing_detected(self):
        text = "We share your data with third-party advertising partners."
        result = self.fn(text)
        assert result["data_sharing"] is True

    def test_retention_detected(self):
        text = "We retain your personal data for 24 months after account closure."
        result = self.fn(text)
        assert result["data_retention"] is True

    def test_user_rights_detected(self):
        text = "You have the right to access, correct, or delete your personal data."
        result = self.fn(text)
        assert result["user_access_rights"] is True

    def test_opt_out_detected(self):
        text = "You can opt-out of marketing emails at any time."
        result = self.fn(text)
        assert result["user_choice_control"] is True

    def test_all_categories_present_in_result(self):
        from tools import _PRACTICE_CATEGORIES
        result = self.fn("some policy text")
        for cat in _PRACTICE_CATEGORIES:
            assert cat in result, f"Category '{cat}' missing from result"


class TestAITrainingDetection:
    def setup_method(self):
        from tools import _detect_ai_training
        self.fn = _detect_ai_training

    def test_explicit_training_high(self):
        text = "We use your data to train our AI models and improve performance."
        result = self.fn(text)
        ids = [h["id"] for h in result]
        assert "explicit_training" in ids
        high = [h for h in result if h["id"] == "explicit_training"]
        assert high[0]["severity"] == "HIGH"

    def test_product_improvement_medium(self):
        text = "We may use aggregate data to improve our products and services."
        result = self.fn(text)
        ids = [h["id"] for h in result]
        assert "product_improvement_catchall" in ids
        med = [h for h in result if h["id"] == "product_improvement_catchall"]
        assert med[0]["severity"] == "MEDIUM"

    def test_no_flags_on_clean_text(self):
        text = "We store your data securely and do not use it beyond the stated purpose."
        result = self.fn(text)
        assert result == []

    def test_match_includes_excerpt(self):
        text = "We use your data to train our AI models for better predictions."
        result = self.fn(text)
        assert result
        assert result[0]["matches"]
        assert "excerpt" in result[0]["matches"][0]


class TestRequiredElements:
    def setup_method(self):
        from tools import _check_required_elements
        self.fn = _check_required_elements

    def test_gdpr_retention_present(self):
        text = "We retain your data for 12 months after you close your account."
        result = self.fn(text, "gdpr")
        assert result.get("retention_periods") is True

    def test_gdpr_dpo_present(self):
        text = "Our data protection officer can be reached at dpo@example.com."
        result = self.fn(text, "gdpr")
        assert result.get("dpo_contact") is True

    def test_gdpr_rights_present(self):
        text = "You have the right to access, erasure, and portability of your data."
        result = self.fn(text, "gdpr")
        assert result.get("data_subject_rights") is True

    def test_gdpr_cross_border_present(self):
        text = "We transfer data outside the EU using Standard Contractual Clauses."
        result = self.fn(text, "gdpr")
        assert result.get("cross_border_transfers") is True

    def test_ccpa_do_not_sell_present(self):
        text = "California residents may click 'Do Not Sell or Share My Personal Information'."
        result = self.fn(text, "ccpa_cpra")
        assert result.get("do_not_sell_or_share_link") is True

    def test_unknown_jurisdiction_returns_empty(self):
        result = self.fn("some text", "nonexistent_jurisdiction")
        assert result == {}

    def test_all_gdpr_elements_checked(self):
        from tools import _JURISDICTION_PATTERNS
        gdpr = next(j for j in _JURISDICTION_PATTERNS if j["id"] == "gdpr")
        result = self.fn("some text", "gdpr")
        for element in gdpr["required"]:
            assert element in result, f"Element '{element}' not checked"


class TestStripHtml:
    def setup_method(self):
        from tools import _strip_html
        self.fn = _strip_html

    def test_basic_tags_stripped(self):
        assert self.fn("<p>Hello <b>world</b></p>") == "Hello world"

    def test_script_removed(self):
        result = self.fn("<html><script>alert(1);</script><p>text</p></html>")
        assert "alert" not in result
        assert "text" in result

    def test_style_removed(self):
        result = self.fn("<style>.cls { color: red; }</style><p>content</p>")
        assert "color" not in result
        assert "content" in result

    def test_whitespace_normalised(self):
        result = self.fn("<p>lots   of    spaces</p>")
        assert "  " not in result

    def test_html_entities_decoded(self):
        result = self.fn("AT&amp;T &lt;phones&gt;")
        assert "AT&T" in result


class TestTrackerPatterns:
    def setup_method(self):
        from tools import _TRACKER_DB
        self.db = _TRACKER_DB

    def _match_tracker(self, tracker_id: str, text: str) -> bool:
        entry = next((t for t in self.db if t["id"] == tracker_id), None)
        assert entry is not None, f"Tracker '{tracker_id}' not in DB"
        return any(re.search(p, text, re.IGNORECASE) for p in entry["patterns"])

    def test_meta_pixel_fbevents(self):
        assert self._match_tracker(
            "meta_pixel",
            '<script src="https://connect.facebook.net/en_US/fbevents.js"></script>'
        )

    def test_meta_pixel_fbq(self):
        assert self._match_tracker("meta_pixel", "fbq('track', 'PageView');")

    def test_ga4_gtag(self):
        assert self._match_tracker(
            "ga4",
            '<script async src="https://www.googletagmanager.com/gtag/js?id=G-ABC12345"></script>'
        )

    def test_gtm_container(self):
        assert self._match_tracker(
            "google_tag_manager",
            "https://www.googletagmanager.com/gtm.js?id=GTM-XXXX"
        )

    def test_fingerprint_js(self):
        assert self._match_tracker(
            "fingerprint_js",
            "import FingerprintJS from '@fingerprintjs/fingerprintjs';"
        )

    def test_hotjar(self):
        assert self._match_tracker(
            "hotjar",
            "https://static.hotjar.com/c/hotjar-1234.js"
        )

    def test_tiktok_pixel(self):
        assert self._match_tracker(
            "tiktok_pixel",
            "ttq.load('C12345678');"
        )

    def test_onetrust_consent(self):
        assert self._match_tracker(
            "onetrust",
            "https://cdn.cookielaw.org/consent/abc/OtAutoBlock.js"
        )

    def test_no_false_positive_on_clean_page(self):
        html = "<html><body><p>Hello world, welcome to our site.</p></body></html>"
        for tracker in self.db:
            matched = any(re.search(p, html, re.IGNORECASE) for p in tracker["patterns"])
            assert not matched, f"False positive: tracker '{tracker['id']}' matched clean page"


class TestContextEscalation:
    """scan_trackers should escalate risk for high-risk page contexts."""

    def _build_mock_response(self, html: str) -> MagicMock:
        resp = MagicMock()
        resp.status_code = 200
        resp.text = html
        resp.url = "https://example.com"
        return resp

    def test_healthcare_context_escalates_medium_tracker(self):
        from tools import scan_trackers
        html = (
            "We are a hospital serving patients. "
            "fbq('track', 'PageView');  "  # Meta Pixel HIGH — won't change
            "<script src='https://static.hotjar.com/c/hotjar-1234.js'></script>"  # Hotjar MEDIUM
            " health medical hospital"
        )
        with patch("tools.requests.get") as mock_get:
            mock_get.return_value = self._build_mock_response(html)
            result = scan_trackers("example.com")

        assert "healthcare" in result["context_flags"]
        hotjar_entry = next((t for t in result["trackers_detected"] if t["id"] == "hotjar"), None)
        assert hotjar_entry is not None
        assert hotjar_entry.get("risk_escalated_to") == "HIGH"

    def test_no_escalation_without_context(self):
        from tools import scan_trackers
        html = "<script src='https://static.hotjar.com/c/hotjar-1234.js'></script>"
        with patch("tools.requests.get") as mock_get:
            mock_get.return_value = self._build_mock_response(html)
            result = scan_trackers("example.com")

        assert result["context_flags"] == []
        hotjar = next((t for t in result["trackers_detected"] if t["id"] == "hotjar"), None)
        if hotjar:
            assert "risk_escalated_to" not in hotjar


# ---------------------------------------------------------------------------
# Tier 2: Pure logic — tech-stack
# ---------------------------------------------------------------------------

class TestDetectAtsInText:
    def setup_method(self):
        from tools import _detect_ats_in_text
        self.fn = _detect_ats_in_text

    def test_greenhouse_board_url(self):
        result = self.fn("https://boards.greenhouse.io/stripe")
        assert result
        r = result[0]
        assert r["ats"] == "greenhouse"
        assert r["handle"] == "stripe"
        assert r["board_url"] == "https://boards.greenhouse.io/stripe"
        assert r["has_api"] is True

    def test_lever_url(self):
        result = self.fn("https://jobs.lever.co/acmecorp")
        assert result
        assert result[0]["ats"] == "lever"
        assert result[0]["handle"] == "acmecorp"

    def test_personio_url(self):
        result = self.fn("https://mycompany.jobs.personio.de")
        assert result
        assert result[0]["ats"] == "personio"
        assert result[0]["handle"] == "mycompany"
        assert result[0]["board_url"] == "https://mycompany.jobs.personio.de"

    def test_recruitee_subdomain(self):
        result = self.fn("https://acmecorp.recruitee.com")
        assert result
        assert result[0]["ats"] == "recruitee"
        assert result[0]["handle"] == "acmecorp"

    def test_platform_subdomain_excluded(self):
        # 'apply' is in _ATS_PLATFORM_SUBDOMAINS — must not be returned as a handle
        result = self.fn("https://apply.workable.com")
        assert all(r["handle"].lower() != "apply" for r in result)

    def test_board_url_in_result(self):
        result = self.fn("https://jobs.lever.co/acmecorp")
        assert result[0]["board_url"] == "https://jobs.lever.co/acmecorp"

    def test_no_false_positive_on_generic_url(self):
        result = self.fn("https://example.com/about/careers")
        assert result == []

    def test_deduplication(self):
        # Same ATS handle appearing twice in text should yield one result
        text = "https://boards.greenhouse.io/stripe jobs at boards.greenhouse.io/stripe"
        result = self.fn(text)
        stripe_hits = [r for r in result if r["handle"] == "stripe"]
        assert len(stripe_hits) == 1


class TestFetchJobPostings:
    """Test fetch_job_postings with unrecognized and no-API ATS URLs."""

    def test_unknown_url_returns_error(self):
        from tools import fetch_job_postings
        result = fetch_job_postings("https://example.com/careers/jobs")
        assert "error" in result

    def test_no_api_ats_returns_error(self):
        from tools import fetch_job_postings
        # Teamtailor has no public API
        result = fetch_job_postings("https://acmecorp.teamtailor.com")
        assert "error" in result
        assert result.get("ats") == "teamtailor"


# ---------------------------------------------------------------------------
# Tier 2: Pure logic — LLM recon
# ---------------------------------------------------------------------------

class TestLlmSecurityProbeGating:
    def setup_method(self):
        from tools import llm_security_probe
        self.fn = llm_security_probe

    def test_refuses_without_authorized_flag(self):
        result = self.fn("https://example.com", authorized=False,
                         authorization_note="pentest engagement 123")
        assert "error" in result

    def test_refuses_without_authorization_note(self):
        result = self.fn("https://example.com", authorized=True, authorization_note="")
        assert "error" in result

    def test_refuses_with_whitespace_only_note(self):
        result = self.fn("https://example.com", authorized=True, authorization_note="   ")
        assert "error" in result


class TestLlmProviderSignals:
    def setup_method(self):
        from tools import _LLM_PROVIDER_SIGNALS, _LLM_LEAKED_KEY_PATTERNS
        self.signals = _LLM_PROVIDER_SIGNALS
        self.key_patterns = _LLM_LEAKED_KEY_PATTERNS

    def test_openai_key_pattern(self):
        # Credential patterns live in _LLM_LEAKED_KEY_PATTERNS, keyed by kind
        openai_kinds = {k: v for k, v in self.key_patterns.items() if "openai" in k}
        assert openai_kinds, "Should have OpenAI credential patterns in _LLM_LEAKED_KEY_PATTERNS"
        assert any(re.search(p, "sk-proj-abc123def456ghi789jkl012mno") for p in openai_kinds.values())

    def test_anthropic_key_pattern(self):
        anthropic_kinds = {k: v for k, v in self.key_patterns.items() if "anthropic" in k}
        assert anthropic_kinds, "Should have Anthropic credential patterns in _LLM_LEAKED_KEY_PATTERNS"
        assert any(re.search(p, "sk-ant-api03-" + "A" * 42) for p in anthropic_kinds.values())

    def test_openai_header_pattern(self):
        # Headers are listed under the 'headers' key in _LLM_PROVIDER_SIGNALS
        headers = self.signals.get("openai", {}).get("headers", [])
        assert headers, "OpenAI should have header signals"


# ---------------------------------------------------------------------------
# Tier 2: Pure logic — core regression
# ---------------------------------------------------------------------------

class TestParseCertDate:
    def setup_method(self):
        from tools import _parse_cert_date
        self.fn = _parse_cert_date

    def test_iso_with_z(self):
        result = self.fn("2024-01-15T10:30:00Z")
        assert result is not None
        assert result.year == 2024
        assert result.tzinfo is not None

    def test_iso_with_offset(self):
        result = self.fn("2024-06-01T12:00:00+02:00")
        assert result is not None
        assert result.year == 2024

    def test_plain_date(self):
        result = self.fn("2024-03-20")
        assert result is not None
        assert result.year == 2024

    def test_invalid_raises(self):
        with pytest.raises(ValueError):
            self.fn("not-a-date")


class TestAtsProvidersStructure:
    def setup_method(self):
        from tools import _ATS_PROVIDERS
        self.providers = _ATS_PROVIDERS

    def test_all_providers_have_patterns(self):
        for name, spec in self.providers.items():
            assert "patterns" in spec and spec["patterns"], \
                f"Provider '{name}' missing patterns"

    def test_all_providers_have_board_url_template(self):
        for name, spec in self.providers.items():
            assert "board_url_template" in spec and spec["board_url_template"], \
                f"Provider '{name}' missing board_url_template"

    def test_api_providers_have_list_key(self):
        for name, spec in self.providers.items():
            if spec.get("api"):
                assert "list_key" in spec, f"API provider '{name}' missing list_key"

    def test_platform_subdomains_excluded(self):
        from tools import _ATS_PLATFORM_SUBDOMAINS, _detect_ats_in_text
        for subdomain in ["apply", "jobs", "careers", "www", "boards"]:
            results = _detect_ats_in_text(f"https://{subdomain}.workable.com")
            handles = [r["handle"].lower() for r in results]
            assert subdomain not in handles, \
                f"Platform subdomain '{subdomain}' incorrectly captured as handle"


# ---------------------------------------------------------------------------
# Tier 3: Mocked HTTP — privacy tools
# ---------------------------------------------------------------------------

def _mock_response(text: str, status: int = 200, url: str = "https://example.com") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.text = text
    resp.url = url
    return resp


GDPR_POLICY_HTML = """
<html><body>
<h1>Privacy Policy</h1>
<p>Last updated: January 1, 2024</p>
<p>We comply with the General Data Protection Regulation (GDPR). Our company is the
data controller. Our data protection officer can be reached at dpo@example.com.</p>
<p>We collect your name, email address, and usage data. We use this data to provide
our services under a contractual necessity basis. We also process data under legitimate
interests for product improvement.</p>
<p>We retain your personal data for 24 months. We share your data with service providers
and third-party vendors under data processing agreements.</p>
<p>You have the right to access, rectify, and erase your personal data. You may also
request data portability or object to processing. You have the right to withdraw consent
at any time. You may lodge a complaint with your supervisory authority.</p>
<p>Where we transfer data outside the EU, we use Standard Contractual Clauses (SCCs).</p>
</body></html>
"""

CCPA_POLICY_HTML = """
<html><body>
<h1>Privacy Policy</h1>
<p>California Consumer Privacy Act (CCPA) — California residents have additional rights.</p>
<p>We collect the following categories of personal information: identifiers, usage data,
and commercial information.</p>
<p>We use this data for our business purposes and do not sell personal information.</p>
<p>Do Not Sell or Share My Personal Information: California residents may submit a request.</p>
<p>California residents have the right to know, delete, and opt-out.</p>
</body></html>
"""

TRACKER_HTML = """
<html>
<head>
<script>
  !function(f,b,e,v,n,t,s){fbq('init', '123456789012345');}(window,
  document,'script','https://connect.facebook.net/en_US/fbevents.js');
  fbq('track', 'PageView');
</script>
<script async src="https://www.googletagmanager.com/gtag/js?id=G-ABCD1234EF"></script>
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){dataLayer.push(arguments);}
  gtag('js', new Date());
  gtag('config', 'G-ABCD1234EF');
</script>
</head>
<body><p>Hello world</p></body>
</html>
"""

AI_TRAINING_HTML = """
<html><body>
<h1>Terms of Service</h1>
<p>By using our service, you agree that we may use your content to train our AI models
and to improve our products and services. You can opt-out of AI training via Data Controls
in Account Settings.</p>
</body></html>
"""


class TestGetPrivacyPolicyMocked:
    def _make_mock(self, html: str, url: str = "https://example.com/privacy-policy"):
        resp = _mock_response(html, url=url)
        return resp

    def test_gdpr_jurisdiction_detected(self):
        from tools import get_privacy_policy
        with patch("tools.requests.get") as mock_get:
            mock_get.return_value = self._make_mock(GDPR_POLICY_HTML)
            result = get_privacy_policy("example.com")

        ids = [j["id"] for j in result["jurisdictions_detected"]]
        assert "gdpr" in ids

    def test_gdpr_gap_analysis_present(self):
        from tools import get_privacy_policy
        with patch("tools.requests.get") as mock_get:
            mock_get.return_value = self._make_mock(GDPR_POLICY_HTML)
            result = get_privacy_policy("example.com")

        assert "gdpr" in result["compliance_gaps"]
        gap = result["compliance_gaps"]["gdpr"]
        assert "present" in gap
        assert "missing" in gap
        assert "retention_periods" in gap["present"]
        assert "dpo_contact" in gap["present"]
        assert "data_subject_rights" in gap["present"]

    def test_ccpa_jurisdiction_detected(self):
        from tools import get_privacy_policy
        with patch("tools.requests.get") as mock_get:
            mock_get.return_value = self._make_mock(CCPA_POLICY_HTML)
            result = get_privacy_policy("example.com")

        ids = [j["id"] for j in result["jurisdictions_detected"]]
        assert "ccpa_cpra" in ids

    def test_practice_categories_populated(self):
        from tools import get_privacy_policy
        with patch("tools.requests.get") as mock_get:
            mock_get.return_value = self._make_mock(GDPR_POLICY_HTML)
            result = get_privacy_policy("example.com")

        cats = result["practice_categories"]
        assert cats.get("data_collection") is True
        assert cats.get("data_sharing") is True
        assert cats.get("data_retention") is True
        assert cats.get("user_access_rights") is True

    def test_ai_training_flags_detected(self):
        from tools import get_privacy_policy
        with patch("tools.requests.get") as mock_get:
            mock_get.return_value = self._make_mock(AI_TRAINING_HTML)
            result = get_privacy_policy("example.com")

        flags = result["ai_training_indicators"]
        assert any(f["id"] == "explicit_training" for f in flags), \
            "Should detect explicit AI training clause"

    def test_network_error_returns_empty_gracefully(self):
        from tools import get_privacy_policy
        import requests
        with patch("tools.requests.get", side_effect=requests.exceptions.ConnectionError("offline")):
            result = get_privacy_policy("example.com")

        assert result["word_count"] == 0
        assert result["jurisdictions_detected"] == []

    def test_result_keys_present(self):
        from tools import get_privacy_policy
        with patch("tools.requests.get") as mock_get:
            mock_get.return_value = self._make_mock(GDPR_POLICY_HTML)
            result = get_privacy_policy("example.com")

        for key in ["domain", "documents_found", "jurisdictions_detected",
                    "practice_categories", "ai_training_indicators",
                    "compliance_gaps", "query_info"]:
            assert key in result, f"Missing key '{key}'"

    def test_last_updated_extracted(self):
        from tools import get_privacy_policy
        with patch("tools.requests.get") as mock_get:
            mock_get.return_value = self._make_mock(GDPR_POLICY_HTML)
            result = get_privacy_policy("example.com")

        assert result["last_updated"] is not None
        assert "2024" in result["last_updated"]


class TestScanTrackersMocked:
    def _make_mock(self, html: str) -> MagicMock:
        return _mock_response(html)

    def test_meta_pixel_detected(self):
        from tools import scan_trackers
        with patch("tools.requests.get") as mock_get:
            mock_get.return_value = self._make_mock(TRACKER_HTML)
            result = scan_trackers("example.com")

        ids = [t["id"] for t in result["trackers_detected"]]
        assert "meta_pixel" in ids

    def test_ga4_detected(self):
        from tools import scan_trackers
        with patch("tools.requests.get") as mock_get:
            mock_get.return_value = self._make_mock(TRACKER_HTML)
            result = scan_trackers("example.com")

        ids = [t["id"] for t in result["trackers_detected"]]
        assert "ga4" in ids

    def test_contradiction_hints_fire_for_meta_pixel(self):
        from tools import scan_trackers
        with patch("tools.requests.get") as mock_get:
            mock_get.return_value = self._make_mock(TRACKER_HTML)
            result = scan_trackers("example.com")

        hint_types = [h["type"] for h in result["contradiction_hints"]]
        assert "do_not_share_contradiction" in hint_types

    def test_ga4_cross_border_hint_fires(self):
        from tools import scan_trackers
        with patch("tools.requests.get") as mock_get:
            mock_get.return_value = self._make_mock(TRACKER_HTML)
            result = scan_trackers("example.com")

        hint_types = [h["type"] for h in result["contradiction_hints"]]
        assert "cross_border_transfer_contradiction" in hint_types

    def test_onetrust_classified_as_consent_not_tracker(self):
        from tools import scan_trackers
        html = '<script src="https://cdn.cookielaw.org/consent/abc/OtAutoBlock.js"></script>'
        with patch("tools.requests.get") as mock_get:
            mock_get.return_value = self._make_mock(html)
            result = scan_trackers("example.com")

        consent_ids = [c["id"] for c in result["consent_mechanisms"]]
        tracker_ids = [t["id"] for t in result["trackers_detected"]]
        assert "onetrust" in consent_ids
        assert "onetrust" not in tracker_ids

    def test_hipaa_hint_fires_for_healthcare_meta_pixel(self):
        from tools import scan_trackers
        html = (
            "We serve hospital patients and provide health and medical services. "
            "fbq('track', 'PageView');"
        )
        with patch("tools.requests.get") as mock_get:
            mock_get.return_value = self._make_mock(html)
            result = scan_trackers("example.com")

        assert "healthcare" in result["context_flags"]
        pixel_hint = next(
            (h for h in result["contradiction_hints"] if h.get("type") == "do_not_share_contradiction"),
            None
        )
        assert pixel_hint is not None
        assert "hipaa_risk" in pixel_hint

    def test_no_consent_banner_hint_when_ads_present(self):
        from tools import scan_trackers
        # Only Meta Pixel, no consent banner
        html = "fbq('track', 'PageView');"
        with patch("tools.requests.get") as mock_get:
            mock_get.return_value = self._make_mock(html)
            result = scan_trackers("example.com")

        hint_types = [h["type"] for h in result["contradiction_hints"]]
        assert "no_consent_mechanism" in hint_types

    def test_clean_page_no_trackers(self):
        from tools import scan_trackers
        html = "<html><body><p>Hello world</p></body></html>"
        with patch("tools.requests.get") as mock_get:
            mock_get.return_value = self._make_mock(html)
            result = scan_trackers("example.com")

        assert result["tracker_count"] == 0
        assert result["contradiction_hints"] == []

    def test_result_keys_present(self):
        from tools import scan_trackers
        with patch("tools.requests.get") as mock_get:
            mock_get.return_value = self._make_mock("<html></html>")
            result = scan_trackers("example.com")

        for key in ["domain", "trackers_detected", "consent_mechanisms",
                    "tracker_count", "by_category", "by_risk",
                    "contradiction_hints", "context_flags", "query_info"]:
            assert key in result, f"Missing key '{key}'"

    def test_network_error_returns_gracefully(self):
        from tools import scan_trackers
        import requests
        with patch("tools.requests.get", side_effect=requests.exceptions.ConnectionError):
            result = scan_trackers("example.com")

        assert result["tracker_count"] == 0
        assert result["fetch_error"] is not None


# ---------------------------------------------------------------------------
# Tier 3: Mocked HTTP — tech-stack tools
# ---------------------------------------------------------------------------

GREENHOUSE_API_RESPONSE = {
    "jobs": [
        {
            "title": "Senior Python Engineer",
            "content": (
                "We use Python, FastAPI, PostgreSQL, Redis, Kubernetes, "
                "AWS, Terraform, and Datadog. Experience with React and TypeScript helpful."
            ),
            "location": {"name": "Remote"},
            "updated_at": "2024-01-01T00:00:00Z",
        },
        {
            "title": "Data Engineer",
            "content": "Must know Python, Kafka, dbt, Snowflake, Airflow, AWS.",
            "location": {"name": "London"},
            "updated_at": "2024-01-02T00:00:00Z",
        },
    ]
}


class TestFetchJobPostingsMocked:
    def test_greenhouse_keywords_extracted(self):
        from tools import fetch_job_postings
        board_url = "https://boards.greenhouse.io/acmecorp"
        with patch("tools.requests.get") as mock_get:
            mock_get.return_value = _mock_response(
                json.dumps(GREENHOUSE_API_RESPONSE),
                url=f"https://boards-api.greenhouse.io/v1/boards/acmecorp/jobs"
            )
            mock_get.return_value.json.return_value = GREENHOUSE_API_RESPONSE
            mock_get.return_value.raise_for_status = MagicMock()
            result = fetch_job_postings(board_url)

        assert result.get("ats") == "greenhouse"
        assert result.get("handle") == "acmecorp"
        assert result.get("total_jobs") == 2
        agg = result.get("aggregated_tech_keywords", {})
        # Python appears in both postings → should be top-ranked
        all_keywords = [kw for pairs in agg.values() for kw, _ in pairs]
        assert "python" in all_keywords

    def test_greenhouse_board_url_in_result(self):
        from tools import fetch_job_postings
        with patch("tools.requests.get") as mock_get:
            mock_get.return_value = _mock_response("")
            mock_get.return_value.json.return_value = GREENHOUSE_API_RESPONSE
            mock_get.return_value.raise_for_status = MagicMock()
            result = fetch_job_postings("https://boards.greenhouse.io/acmecorp")

        assert result.get("board_url") == "https://boards.greenhouse.io/acmecorp"

    def test_api_error_returns_error_key(self):
        from tools import fetch_job_postings
        import requests
        with patch("tools.requests.get") as mock_get:
            mock_get.return_value = _mock_response("", status=404)
            mock_get.return_value.raise_for_status.side_effect = \
                requests.exceptions.HTTPError("404")
            result = fetch_job_postings("https://boards.greenhouse.io/acmecorp")

        assert "error" in result


class TestFindCareerSourcesMocked:
    def test_greenhouse_redirect_detected(self):
        from tools import find_career_sources
        resp = _mock_response(
            '<a href="https://boards.greenhouse.io/acmecorp">Jobs</a>',
            url="https://boards.greenhouse.io/acmecorp",
        )
        import requests as req_module
        with patch("tools.requests.get") as mock_get:
            mock_get.return_value = resp
            result = find_career_sources("example.com")

        ats_ids = [a["ats"] for a in result["ats_discovered"]]
        assert "greenhouse" in ats_ids

    def test_result_structure(self):
        from tools import find_career_sources
        with patch("tools.requests.get") as mock_get:
            mock_get.return_value = _mock_response("<html></html>")
            result = find_career_sources("example.com")

        for key in ["domain", "ats_discovered", "live_careers_urls",
                    "wayback_snapshots", "errors", "query_info"]:
            assert key in result

    def test_all_http_errors_handled(self):
        from tools import find_career_sources
        import requests
        with patch("tools.requests.get",
                   side_effect=requests.exceptions.ConnectionError("offline")):
            result = find_career_sources("example.com")

        assert result["ats_discovered"] == []
        assert len(result["errors"]) > 0


# ---------------------------------------------------------------------------
# Tier 3: Mocked HTTP — LLM tools
# ---------------------------------------------------------------------------

class TestLlmFingerprintMocked:
    def _build_resp(self, status=200, headers=None, text="<html></html>", url=None):
        resp = MagicMock()
        resp.status_code = status
        resp.headers = headers or {}
        resp.text = text
        resp.url = url or "https://example.com"
        resp.content = text.encode()
        return resp

    def test_openai_key_in_js_detected(self):
        from tools import llm_fingerprint
        html = """
        <html><head>
        <script>const OPENAI_KEY = "sk-proj-abc123def456ghi789jkl";</script>
        </head><body></body></html>
        """
        with patch("tools.requests.get") as mock_get:
            mock_get.return_value = self._build_resp(text=html)
            result = llm_fingerprint("https://example.com")

        assert result.get("leaked_credentials"), "Should detect leaked OpenAI key"
        # credential items have a 'kind' key (e.g. 'openai_project'), not 'provider'
        assert any("openai" in c["kind"]
                   for c in result.get("leaked_credentials", []))

    def test_result_keys_present(self):
        from tools import llm_fingerprint
        with patch("tools.requests.get") as mock_get:
            mock_get.return_value = self._build_resp()
            result = llm_fingerprint("https://example.com")

        for key in ["url", "providers", "frameworks",
                    "leaked_credentials", "owasp_findings", "query_info"]:
            assert key in result, f"Missing key '{key}'"

    def test_network_error_returns_gracefully(self):
        from tools import llm_fingerprint
        import requests
        with patch("tools.requests.get",
                   side_effect=requests.exceptions.ConnectionError):
            result = llm_fingerprint("https://example.com")

        assert "error" in result or "providers" in result


# ---------------------------------------------------------------------------
# Tier 3: Mocked HTTP — core regression
# ---------------------------------------------------------------------------

SECURITY_TXT_CONTENT = """Contact: mailto:security@example.com
Contact: https://example.com/security
Expires: 2027-01-01T00:00:00Z
Encryption: https://example.com/pgp.txt
Policy: https://example.com/security-policy
Preferred-Languages: en, de
"""


class TestSecurityTxtRegression:
    def test_contact_parsed(self):
        from tools import get_security_txt
        resp = _mock_response(SECURITY_TXT_CONTENT,
                              url="https://example.com/.well-known/security.txt")
        with patch("tools.requests.get") as mock_get:
            mock_get.return_value = resp
            result = get_security_txt("example.com")

        assert result.get("found") is True
        # contacts are nested under result['fields']['contact']
        contacts = result.get("fields", {}).get("contact", [])
        assert any("security@example.com" in c for c in contacts)

    def test_policy_parsed(self):
        from tools import get_security_txt
        resp = _mock_response(SECURITY_TXT_CONTENT,
                              url="https://example.com/.well-known/security.txt")
        with patch("tools.requests.get") as mock_get:
            mock_get.return_value = resp
            result = get_security_txt("example.com")

        # policy is a list nested under result['fields']['policy']
        policy_list = result.get("fields", {}).get("policy", [])
        assert "https://example.com/security-policy" in policy_list

    def test_not_expired_for_future_date(self):
        from tools import get_security_txt
        resp = _mock_response(SECURITY_TXT_CONTENT,
                              url="https://example.com/.well-known/security.txt")
        with patch("tools.requests.get") as mock_get:
            mock_get.return_value = resp
            result = get_security_txt("example.com")

        assert result.get("is_expired") is False

    def test_404_returns_not_found(self):
        from tools import get_security_txt
        with patch("tools.requests.get") as mock_get:
            mock_get.return_value = _mock_response("", status=404)
            result = get_security_txt("example.com")

        assert result.get("found") is False


CERTSPOTTER_RESPONSE = [
    {
        "id": "12345",
        "tbs_sha256": "abc123",
        "dns_names": ["example.com", "www.example.com", "api.example.com"],
        "not_before": "2024-01-01T00:00:00Z",
        "not_after": "2025-01-01T00:00:00Z",
        "revoked": False,
        "cert_sha256": "def456",
    }
]


class TestCertificateInfoRegression:
    def test_certspotter_domains_returned(self):
        from tools import get_certificate_info
        with patch("tools.requests.get") as mock_get:
            mock_get.return_value = _mock_response(
                json.dumps(CERTSPOTTER_RESPONSE)
            )
            mock_get.return_value.json.return_value = CERTSPOTTER_RESPONSE
            # include_expired=True because the fixture cert expired 2025-01-01
            result = get_certificate_info("example.com", include_expired=True)

        assert "certificates" in result or "error" in result
        if "certificates" in result:
            certs = result["certificates"]
            assert len(certs) >= 1
            # domains are in c['domains'], not c['dns_names']
            all_domains = [d for c in certs for d in c.get("domains", [])]
            assert "example.com" in all_domains

    def test_result_has_sources_used(self):
        from tools import get_certificate_info
        with patch("tools.requests.get") as mock_get:
            mock_get.return_value = _mock_response(
                json.dumps(CERTSPOTTER_RESPONSE)
            )
            mock_get.return_value.json.return_value = CERTSPOTTER_RESPONSE
            result = get_certificate_info("example.com", include_expired=True)

        if "certificates" in result:
            # sources_used is nested inside query_info
            assert "sources_used" in result.get("query_info", {})


# ---------------------------------------------------------------------------
# Tier 3: Mocked HTTP — Web Search / Research tools
# ---------------------------------------------------------------------------

def _mock_json_response(data: dict, status: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.reason = "OK" if status == 200 else "Error"
    resp.json.return_value = data
    resp.raise_for_status.return_value = None
    return resp


class TestSearchBraveMocked:
    BRAVE_RESPONSE = {
        "web": {
            "totalCount": 1234,
            "results": [
                {"title": "Example Site", "url": "https://example.com", "description": "An example.", "age": "2 days ago"},
                {"title": "Another Site", "url": "https://other.com", "description": "Another.", "age": None},
            ],
        }
    }

    def test_success_returns_results(self):
        from tools import search_brave
        with patch("tools.requests.get") as mock_get:
            mock_get.return_value = _mock_json_response(self.BRAVE_RESPONSE)
            result = search_brave("key123", "test query")

        assert result["query"] == "test query"
        assert len(result["results"]) == 2
        assert result["results"][0]["title"] == "Example Site"
        assert result["results"][0]["url"] == "https://example.com"
        assert result["total_estimated"] == 1234

    def test_success_has_telemetry(self):
        from tools import search_brave
        with patch("tools.requests.get") as mock_get:
            mock_get.return_value = _mock_json_response(self.BRAVE_RESPONSE)
            result = search_brave("key123", "test query")

        assert "_telemetry" in result
        assert "duration_ms" in result["_telemetry"]
        assert result["_telemetry"]["quality"] == 1.0

    def test_empty_results_quality_half(self):
        from tools import search_brave
        with patch("tools.requests.get") as mock_get:
            mock_get.return_value = _mock_json_response({"web": {"totalCount": 0, "results": []}})
            result = search_brave("key123", "obscure query")

        assert result["results"] == []
        assert result["_telemetry"]["quality"] == 0.5

    def test_http_error_returns_error_dict(self):
        import requests
        from tools import search_brave
        mock_resp = _mock_json_response({}, status=401)
        mock_resp.raise_for_status.side_effect = requests.exceptions.HTTPError(
            response=mock_resp
        )
        with patch("tools.requests.get", return_value=mock_resp):
            result = search_brave("badkey", "query")

        assert "error" in result
        assert "Brave Search" in result["error"]
        assert result["_telemetry"]["quality"] == 0.0

    def test_network_error_returns_error_dict(self):
        import requests
        from tools import search_brave
        with patch("tools.requests.get", side_effect=requests.exceptions.ConnectionError("offline")):
            result = search_brave("key123", "query")

        assert "error" in result
        assert "Brave Search" in result["error"]
        assert result["_telemetry"]["quality"] == 0.0

    def test_count_clamped_to_20(self):
        from tools import search_brave
        with patch("tools.requests.get") as mock_get:
            mock_get.return_value = _mock_json_response(self.BRAVE_RESPONSE)
            search_brave("key123", "query", count=50)

        _, kwargs = mock_get.call_args
        assert kwargs["params"]["count"] == 20


class TestSearchTavilyMocked:
    TAVILY_RESPONSE = {
        "answer": "This is a synthesised answer.",
        "results": [
            {"title": "Source A", "url": "https://sourcea.com", "content": "Relevant excerpt.", "score": 0.92},
            {"title": "Source B", "url": "https://sourceb.com", "content": "Another excerpt.", "score": 0.85},
        ],
        "response_time": 1.23,
    }

    def test_success_returns_answer_and_results(self):
        from tools import search_tavily
        with patch("tools.requests.post") as mock_post:
            mock_post.return_value = _mock_json_response(self.TAVILY_RESPONSE)
            result = search_tavily("key123", "what is NIS2?")

        assert result["query"] == "what is NIS2?"
        assert result["answer"] == "This is a synthesised answer."
        assert len(result["results"]) == 2
        assert result["results"][0]["score"] == 0.92
        assert result["response_time"] == 1.23

    def test_success_has_telemetry(self):
        from tools import search_tavily
        with patch("tools.requests.post") as mock_post:
            mock_post.return_value = _mock_json_response(self.TAVILY_RESPONSE)
            result = search_tavily("key123", "query")

        assert "_telemetry" in result
        assert result["_telemetry"]["quality"] == 1.0

    def test_null_answer_allowed(self):
        from tools import search_tavily
        data = {**self.TAVILY_RESPONSE, "answer": None}
        with patch("tools.requests.post") as mock_post:
            mock_post.return_value = _mock_json_response(data)
            result = search_tavily("key123", "query")

        assert result["answer"] is None
        assert result["_telemetry"]["quality"] == 1.0  # results still present

    def test_http_error_returns_error_dict(self):
        import requests
        from tools import search_tavily
        mock_resp = _mock_json_response({}, status=429)
        mock_resp.raise_for_status.side_effect = requests.exceptions.HTTPError(
            response=mock_resp
        )
        with patch("tools.requests.post", return_value=mock_resp):
            result = search_tavily("key123", "query")

        assert "error" in result
        assert "Tavily" in result["error"]
        assert result["_telemetry"]["quality"] == 0.0

    def test_network_error_returns_error_dict(self):
        import requests
        from tools import search_tavily
        with patch("tools.requests.post", side_effect=requests.exceptions.Timeout("timed out")):
            result = search_tavily("key123", "query")

        assert "error" in result
        assert "Tavily" in result["error"]
        assert result["_telemetry"]["quality"] == 0.0

    def test_include_answer_sent_in_body(self):
        from tools import search_tavily
        with patch("tools.requests.post") as mock_post:
            mock_post.return_value = _mock_json_response(self.TAVILY_RESPONSE)
            search_tavily("key123", "query", search_depth="advanced", max_results=3)

        _, kwargs = mock_post.call_args
        body = kwargs["json"]
        assert body["include_answer"] is True
        assert body["search_depth"] == "advanced"
        assert body["max_results"] == 3


class TestGetPerplexitySynthesisMocked:
    PERPLEXITY_RESPONSE = {
        "model": "sonar",
        "choices": [{"message": {"content": "NIS2 is the EU cybersecurity directive."}}],
        "citations": ["https://eur-lex.europa.eu/nis2", "https://enisa.europa.eu/nis2"],
    }

    def test_success_returns_answer_and_citations(self):
        from tools import get_perplexity_synthesis
        with patch("tools.requests.post") as mock_post:
            mock_post.return_value = _mock_json_response(self.PERPLEXITY_RESPONSE)
            result = get_perplexity_synthesis("key123", "What is NIS2?")

        assert result["query"] == "What is NIS2?"
        assert result["answer"] == "NIS2 is the EU cybersecurity directive."
        assert len(result["citations"]) == 2
        assert result["model"] == "sonar"

    def test_success_has_telemetry(self):
        from tools import get_perplexity_synthesis
        with patch("tools.requests.post") as mock_post:
            mock_post.return_value = _mock_json_response(self.PERPLEXITY_RESPONSE)
            result = get_perplexity_synthesis("key123", "query")

        assert "_telemetry" in result
        assert result["_telemetry"]["quality"] == 1.0

    def test_empty_answer_quality_half(self):
        from tools import get_perplexity_synthesis
        data = {"model": "sonar", "choices": [{"message": {"content": ""}}], "citations": []}
        with patch("tools.requests.post") as mock_post:
            mock_post.return_value = _mock_json_response(data)
            result = get_perplexity_synthesis("key123", "query")

        assert result["answer"] == ""
        assert result["_telemetry"]["quality"] == 0.5

    def test_http_error_returns_error_dict(self):
        import requests
        from tools import get_perplexity_synthesis
        mock_resp = _mock_json_response({}, status=403)
        mock_resp.raise_for_status.side_effect = requests.exceptions.HTTPError(
            response=mock_resp
        )
        with patch("tools.requests.post", return_value=mock_resp):
            result = get_perplexity_synthesis("badkey", "query")

        assert "error" in result
        assert "Perplexity" in result["error"]
        assert result["_telemetry"]["quality"] == 0.0

    def test_network_error_returns_error_dict(self):
        import requests
        from tools import get_perplexity_synthesis
        with patch("tools.requests.post", side_effect=requests.exceptions.ConnectionError("down")):
            result = get_perplexity_synthesis("key123", "query")

        assert "error" in result
        assert "Perplexity" in result["error"]
        assert result["_telemetry"]["quality"] == 0.0

    def test_bearer_auth_header_sent(self):
        from tools import get_perplexity_synthesis
        with patch("tools.requests.post") as mock_post:
            mock_post.return_value = _mock_json_response(self.PERPLEXITY_RESPONSE)
            get_perplexity_synthesis("mytoken", "query")

        _, kwargs = mock_post.call_args
        assert kwargs["headers"]["Authorization"] == "Bearer mytoken"

    def test_model_override(self):
        from tools import get_perplexity_synthesis
        with patch("tools.requests.post") as mock_post:
            mock_post.return_value = _mock_json_response(self.PERPLEXITY_RESPONSE)
            get_perplexity_synthesis("key123", "query", model="sonar-pro")

        _, kwargs = mock_post.call_args
        assert kwargs["json"]["model"] == "sonar-pro"


# ---------------------------------------------------------------------------
# Tier 3: Mocked HTTP — security.txt (RFC 9116) validation
# ---------------------------------------------------------------------------

VALID_SECURITY_TXT = """\
# Our security policy
Contact: mailto:security@example.com
Expires: 2030-01-01T00:00:00.000Z
Encryption: https://example.com/pgp-key.txt
Policy: https://example.com/security-policy
"""

# A typical SPA/parking page returned with HTTP 200 for /.well-known/security.txt.
SPA_HTML_PAGE = """\
<!DOCTYPE html>
<html lang="en"><head><title>Welcome</title>
<script async src="https://www.googletagmanager.com/gtag/js?id=G-X"></script>
</head><body><a href="https://example.com">home</a></body></html>
"""


def _secjson_resp(text, status=200, content_type="text/plain"):
    resp = MagicMock()
    resp.status_code = status
    resp.text = text
    resp.headers = {"content-type": content_type}
    return resp


class TestGetSecurityTxt:
    def test_valid_security_txt_found(self):
        from tools import get_security_txt
        with patch("tools.requests.get") as mock_get:
            mock_get.return_value = _secjson_resp(VALID_SECURITY_TXT)
            result = get_security_txt("example.com")
        assert result["found"] is True
        assert result["fields"]["contact"] == ["mailto:security@example.com"]
        assert result["fields"]["expires"] == "2030-01-01T00:00:00.000Z"
        assert result["is_expired"] is False

    def test_html_page_rejected(self):
        """An HTML 200 (SPA/parking/404) must NOT be reported as a security.txt."""
        from tools import get_security_txt
        with patch("tools.requests.get") as mock_get:
            mock_get.return_value = _secjson_resp(SPA_HTML_PAGE, content_type="text/html")
            result = get_security_txt("example.com")
        assert result["found"] is False
        assert "raw" not in result          # no HTML blob stored
        assert "fields" not in result       # no garbage fields parsed from HTML

    def test_html_without_content_type_still_rejected(self):
        """Body sniffing catches HTML even if the server mislabels content-type."""
        from tools import get_security_txt
        with patch("tools.requests.get") as mock_get:
            mock_get.return_value = _secjson_resp(SPA_HTML_PAGE, content_type="text/plain")
            result = get_security_txt("example.com")
        assert result["found"] is False

    def test_plaintext_without_directives_rejected(self):
        """Plain text that isn't a security.txt (no RFC 9116 directive) is not found."""
        from tools import get_security_txt
        with patch("tools.requests.get") as mock_get:
            mock_get.return_value = _secjson_resp("hello: world\nfoo: bar\n")
            result = get_security_txt("example.com")
        assert result["found"] is False

    def test_not_found_on_connection_error(self):
        import requests
        from tools import get_security_txt
        with patch("tools.requests.get", side_effect=requests.exceptions.ConnectionError("x")):
            result = get_security_txt("example.com")
        assert result["found"] is False


# ---------------------------------------------------------------------------
# Tier 3: Mocked HTTP — Shodan deep surface search (threat-surface playbook)
# ---------------------------------------------------------------------------

class TestSearchShodanDeep:
    SHODAN_RESULT = {
        "total": 1234,
        "matches": [
            {"ip_str": "1.2.3.4", "port": 443, "org": "Acme", "product": "nginx",
             "location": {"country_name": "US"}, "domains": ["acme.com"]},
            {"ip_str": "1.2.3.5", "port": 3389, "org": "Acme", "product": "RDP",
             "location": {"country_name": "US"}, "domains": []},
        ],
        "facets": {"port": [{"value": "443", "count": 10}, {"value": "3389", "count": 2}]},
    }

    def test_limit_forwarded_to_api(self):
        from tools import search_shodan
        mock_api = MagicMock()
        mock_api.search.return_value = self.SHODAN_RESULT
        with patch("tools.shodan.Shodan", return_value=mock_api):
            search_shodan("key", "asn:AS13335", limit=200)
        # limit must be passed through so the client auto-pages beyond 100 results.
        _, kwargs = mock_api.search.call_args
        assert kwargs.get("limit") == 200

    def test_facets_requested_and_returned(self):
        from tools import search_shodan
        mock_api = MagicMock()
        mock_api.search.return_value = self.SHODAN_RESULT
        with patch("tools.shodan.Shodan", return_value=mock_api):
            result = search_shodan("key", "net:1.2.3.0/24", limit=50, facets="port,org")
        _, kwargs = mock_api.search.call_args
        assert kwargs.get("facets") == ["port", "org"]
        assert result["facets"] == self.SHODAN_RESULT["facets"]

    def test_no_facets_key_null_when_not_requested(self):
        from tools import search_shodan
        mock_api = MagicMock()
        mock_api.search.return_value = self.SHODAN_RESULT
        with patch("tools.shodan.Shodan", return_value=mock_api):
            result = search_shodan("key", "ip:1.2.3.4")
        assert result["facets"] is None
        assert result["matches"][0]["ip"] == "1.2.3.4"

    def test_limit_bounded(self):
        from tools import search_shodan
        mock_api = MagicMock()
        mock_api.search.return_value = self.SHODAN_RESULT
        with patch("tools.shodan.Shodan", return_value=mock_api):
            search_shodan("key", "asn:AS1", limit=999999)
        _, kwargs = mock_api.search.call_args
        assert kwargs.get("limit") == 1000  # capped


class TestShodanDomain:
    # hostname query finds host A; cert query finds host A again + host B (cert-only, e.g. RDP).
    HOSTNAME_RESULT = {
        "total": 1,
        "matches": [
            {"ip_str": "10.0.0.1", "port": 443, "org": "Acme", "product": "nginx",
             "location": {"country_name": "SE"}, "hostnames": ["www.acme.se"]},
        ],
    }
    CERT_RESULT = {
        "total": 2,
        "matches": [
            {"ip_str": "10.0.0.1", "port": 443, "org": "Acme", "product": "nginx",
             "location": {"country_name": "SE"}, "hostnames": ["www.acme.se"]},
            {"ip_str": "10.0.0.2", "port": 3389, "org": "Tele2", "product": "RDP",
             "location": {"country_name": "SE"}, "hostnames": ["laptop.acme.se"]},
        ],
    }

    def test_merges_hostname_and_cert_queries(self):
        from tools import get_shodan_domain
        mock_api = MagicMock()
        # query order in the tool: hostname, then cert.
        mock_api.search.side_effect = [self.HOSTNAME_RESULT, self.CERT_RESULT]
        with patch("tools.shodan.Shodan", return_value=mock_api):
            r = get_shodan_domain("key", "acme.se")

        # both sub-queries issued
        assert mock_api.search.call_count == 2
        # de-duplicated by (ip, port): 10.0.0.1:443 once + 10.0.0.2:3389 once
        keys = {(m["ip"], m["port"]) for m in r["matches"]}
        assert keys == {("10.0.0.1", 443), ("10.0.0.2", 3389)}
        assert r["total_results"] == 2
        # the shared host is matched_by both; the cert-only RDP host is cert-only
        by_ip = {m["ip"]: m for m in r["matches"]}
        assert set(by_ip["10.0.0.1"]["matched_by"]) == {"hostname", "cert"}
        assert by_ip["10.0.0.2"]["matched_by"] == ["cert"]  # caught only by the cert query

    def test_query_strings(self):
        from tools import get_shodan_domain
        mock_api = MagicMock()
        mock_api.search.side_effect = [self.HOSTNAME_RESULT, self.CERT_RESULT]
        with patch("tools.shodan.Shodan", return_value=mock_api):
            r = get_shodan_domain("key", "acme.se")
        assert r["queries"]["hostname"] == "hostname:acme.se"
        assert r["queries"]["cert"] == "ssl.cert.subject.cn:acme.se"

    def test_in_all_and_server_tool(self):
        import tools
        assert "get_shodan_domain" in tools.__all__


class TestThreatSurfacePlaybook:
    def test_playbook_file_exists(self):
        from pathlib import Path
        import tools  # noqa: F401 — anchor for repo root
        path = Path(__file__).resolve().parent.parent / "docs" / "threat-surface.md"
        assert path.exists(), "docs/threat-surface.md must exist"
        text = path.read_text(encoding="utf-8")
        assert "Threat-Surface" in text
        # Mentions the core pivot filters the agent should use.
        for token in ("asn:", "net:", "http.favicon.hash:", "ssl.cert.subject.cn:"):
            assert token in text

    def test_resource_registered(self):
        import server
        assert server._get_threat_surface_content().strip()


# ---------------------------------------------------------------------------
# THC ip.thc.org passive-DNS recon (mocked)
# ---------------------------------------------------------------------------

def _mock_text_response(text: str, status: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.reason = "OK" if status == 200 else "Error"
    resp.text = text
    resp.raise_for_status.return_value = None
    return resp


_THC_IP_TEXT = (
    ";ASN    : 15169 [https://bgpview.io/asn/15169]\n"
    ";Org    : GOOGLE\n"
    ";City   : N/A\n"
    ";Country: United States\n"
    ";GPS    : 37.751000,-97.822000 [https://maps.google.com/?q=37.751,-97.822]\n"
    ";IP     : 8.8.8.8\n"
    ";;Entries: 100/39400 [https://ip.thc.org/8.8.8.8?f=abc to filter]\n"
    ";;Rate Limit: You can make 249 requests (Replenishes at 0.50/sec)\n"
    "dns.google\n"
    "resolver.example\n"
)

_THC_CNAME_TEXT = (
    ";;Domains Pointing To: cdn.example.com\n"
    ";;Entries: 2/2\n"
    ";;Rate Limit: You can make 248 requests (Replenishes at 0.50/sec)\n"
    "shop.acme.se\n"
    "www.acme.se\n"
)

_THC_SUBS_TEXT = (
    ";;Subdomains For: acme.se\n"
    ";;Entries: 3/57\n"
    ";;Rate Limit: You can make 247 requests (Replenishes at 0.50/sec)\n"
    "acme.se\n"
    "mail.acme.se\n"
    "vpn.acme.se\n"
)

_THC_EMPTY_TEXT = (
    ";;Domains Pointing To: nobody.example\n"
    ";;Entries: 0/0\n"
    ";;Rate Limit: You can make 249 requests (Replenishes at 0.50/sec)\n"
    ";;We could not find any domains for nobody.example\n"
)


class TestThcReconMocked:
    def setup_method(self):
        import tools
        tools._thc_last = 0.0  # reset throttle so tests don't sleep

    def test_ip_parses_asn_and_hostnames(self):
        import tools
        with patch("tools.requests.get", return_value=_mock_text_response(_THC_IP_TEXT)):
            r = tools.get_thc_recon("8.8.8.8")
        assert r["kind"] == "ip"
        assert r["asn"] == "15169" and r["org"] == "GOOGLE" and r["country"] == "United States"
        assert "dns.google" in r["reverse_hostnames"]
        assert r["reverse_total"] == 39400
        assert r["_telemetry"]["quality"] == 1.0

    def test_domain_cname_and_subdomains(self):
        import tools
        # two calls: /cn/<d> then /<d>
        with patch("tools.requests.get", side_effect=[
            _mock_text_response(_THC_CNAME_TEXT),
            _mock_text_response(_THC_SUBS_TEXT),
        ]):
            r = tools.get_thc_recon("acme.se")
        assert r["kind"] == "domain"
        assert "shop.acme.se" in r["cname_pointers"] and "www.acme.se" in r["cname_pointers"]
        assert "mail.acme.se" in r["subdomains"]
        assert r["subdomains_total"] == 57
        assert r["_telemetry"]["quality"] == 1.0

    def test_domain_empty_is_benign(self):
        import tools
        with patch("tools.requests.get", side_effect=[
            _mock_text_response(_THC_EMPTY_TEXT),
            _mock_text_response(_THC_EMPTY_TEXT),
        ]):
            r = tools.get_thc_recon("nobody.example")
        assert r["cname_pointers"] == [] and r["subdomains"] == []
        assert "error" not in r
        assert r["_telemetry"]["quality"] == 0.5   # nothing found → empty, not a failure

    def test_cap_limits_entries(self):
        import tools
        big = _THC_IP_TEXT + "\n".join(f"h{i}.example" for i in range(500))
        with patch("tools.requests.get", return_value=_mock_text_response(big)):
            r = tools.get_thc_recon("8.8.8.8", max_entries=10)
        assert len(r["reverse_hostnames"]) == 10

    def test_rate_limited_429(self):
        import tools
        with patch("tools.requests.get", return_value=_mock_text_response("", status=429)):
            r = tools.get_thc_recon("8.8.8.8")
        assert "error" in r and "rate limit" in r["error"].lower()
        assert r["_telemetry"]["quality"] == 0.0

    def test_network_error(self):
        import tools, requests
        with patch("tools.requests.get", side_effect=requests.exceptions.ConnectionError("offline")):
            r = tools.get_thc_recon("8.8.8.8")
        assert "error" in r and "THC lookup failed" in r["error"]
        assert r["_telemetry"]["quality"] == 0.0


def _json_resp(payload, status: int = 200) -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.json.return_value = payload
    r.raise_for_status.return_value = None
    return r


class TestTorNodesMocked:
    def test_tor_exit_detected(self):
        import tools
        payload = {"relays": [{"nickname": "exitnode1", "fingerprint": "ABC123",
                               "flags": ["Running", "Exit", "Fast"], "running": True, "country": "us",
                               "as": "AS1234", "first_seen": "2020-01-01 00:00:00",
                               "last_seen": "2026-06-01 00:00:00"}], "bridges": []}
        with patch("tools.requests.get", return_value=_json_resp(payload)):
            r = tools.get_tor_nodes("1.2.3.4")
        assert r["is_tor_node"] is True and r["is_exit"] is True and r["is_relay"] is True
        assert r["nickname"] == "exitnode1"
        assert r["_telemetry"]["quality"] == 1.0

    def test_relay_not_exit(self):
        import tools
        payload = {"relays": [{"nickname": "guard1", "flags": ["Running", "Guard"], "running": True}], "bridges": []}
        with patch("tools.requests.get", return_value=_json_resp(payload)):
            r = tools.get_tor_nodes("1.2.3.4")
        assert r["is_tor_node"] is True and r["is_exit"] is False

    def test_non_tor_ip(self):
        import tools
        with patch("tools.requests.get", return_value=_json_resp({"relays": [], "bridges": []})):
            r = tools.get_tor_nodes("8.8.8.8")
        assert r["is_tor_node"] is False and r["_telemetry"]["quality"] == 0.5

    def test_invalid_ip(self):
        import tools
        r = tools.get_tor_nodes("not-an-ip")
        assert "error" in r and r["_telemetry"]["quality"] == 0.0


class TestRansomwareCheckMocked:
    def test_victim_found_by_domain(self):
        import tools
        payload = [{"victim": "Acme Corp", "group": "lockbit", "attackdate": "2025-01-01", "country": "US"}]
        with patch("tools.requests.get", return_value=_json_resp(payload)):
            r = tools.get_ransomware_check("acme.com")
        assert r["is_victim"] is True and "lockbit" in r["groups"]
        assert r["search_term"] == "acme" and r["_telemetry"]["quality"] == 1.0

    def test_clean(self):
        import tools
        with patch("tools.requests.get", return_value=_json_resp([])):
            r = tools.get_ransomware_check("nonexistentcorp")
        assert r["is_victim"] is False and r["_telemetry"]["quality"] == 0.5

    def test_rate_limited(self):
        import tools
        with patch("tools.requests.get", return_value=_json_resp({}, status=429)):
            r = tools.get_ransomware_check("acme")
        assert "error" in r


class TestProvenanceManifest:
    def test_telemetry_stamps_source_ref(self):
        import datetime, tools
        t = tools._make_telemetry(datetime.datetime.now(datetime.timezone.utc))
        assert "source" in t
        s = t["source"]
        assert {"cybersleuth_version", "cybersleuth_commit", "cybersleuth_build_date", "retrieved_at"} <= set(s)

    def test_manifest_builds_and_covers_all_tools(self):
        import re, manifest
        m = manifest.build_manifest()
        assert m["service"] == "cybersleuth" and m["tool_count"] == len(manifest.SOURCES)
        # every registered MCP tool has a source entry (no untracked provenance)
        toolnames = set(re.findall(r"@mcp\.tool\(\)\s*\ndef (\w+)\(", open("server.py").read()))
        assert toolnames - set(manifest.SOURCES.keys()) == set()
        # every source entry is a real tool
        assert set(manifest.SOURCES.keys()) - toolnames == set()

    def test_known_tool_providers(self):
        import manifest
        assert manifest.SOURCES["tor_nodes"]["providers"][0]["provider"] == "Tor Project Onionoo"
        assert manifest.SOURCES["vt_ip_report"]["providers"][0]["provider"] == "VirusTotal"
        assert manifest.SOURCES["ransomware_check"]["providers"][0]["provider"] == "ransomware.live"
