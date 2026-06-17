"""Tests for dorking builder and templates."""

from __future__ import annotations

import pytest

from src.dorking.builder import build_dork, from_template
from src.dorking.templates import TEMPLATES, get_template_names, get_template_info


class TestBuildDork:
    """Tests for build_dork() function."""

    def test_query_only(self):
        assert build_dork("passwords") == "passwords"

    def test_site_operator(self):
        result = build_dork("test", site="example.com")
        assert result == "site:example.com test"

    def test_filetype_operator(self):
        result = build_dork("config", filetype="env")
        assert result == "filetype:env config"

    def test_filetype_strips_leading_dot(self):
        result = build_dork("config", filetype=".env")
        assert result == "filetype:env config"

    def test_inurl_operator(self):
        result = build_dork("search", inurl="admin")
        assert result == 'inurl:"admin" search'

    def test_intitle_operator(self):
        result = build_dork("search", intitle="login")
        assert result == 'intitle:"login" search'

    def test_intext_operator(self):
        result = build_dork("search", intext="password")
        assert result == 'intext:"password" search'

    def test_exclude_single(self):
        result = build_dork("query", exclude=["github.com"])
        assert result == "-github.com query"

    def test_exclude_multiple(self):
        result = build_dork("query", exclude=["github.com", "stackoverflow.com"])
        assert "-github.com" in result
        assert "-stackoverflow.com" in result

    def test_exclude_preserves_dash_prefix(self):
        result = build_dork("query", exclude=["-already-prefixed"])
        assert "-already-prefixed" in result
        # Should NOT double the dash
        assert "--already-prefixed" not in result

    def test_all_operators_combined(self):
        result = build_dork(
            "passwords",
            site="example.com",
            filetype="txt",
            inurl="admin",
            intitle="login",
            intext="secret",
            exclude=["github.com"],
        )
        assert result.startswith("site:example.com")
        assert "filetype:txt" in result
        assert 'inurl:"admin"' in result
        assert 'intitle:"login"' in result
        assert 'intext:"secret"' in result
        assert "-github.com" in result
        assert result.endswith("passwords")

    def test_operator_order(self):
        """Operators go before base query, in documented order."""
        result = build_dork("q", site="s.com", filetype="pdf")
        parts = result.split()
        assert parts.index("site:s.com") < parts.index("filetype:pdf")
        assert parts.index("filetype:pdf") < parts.index("q")

    def test_empty_query(self):
        result = build_dork("", site="example.com")
        assert result == "site:example.com"

    def test_empty_everything(self):
        result = build_dork("")
        assert result == ""

    def test_none_operators_ignored(self):
        result = build_dork("test", site=None, filetype=None, inurl=None)
        assert result == "test"


class TestFromTemplate:
    """Tests for from_template() function."""

    def test_exposed_configs_template(self):
        result = from_template("exposed_configs", domain="target.com")
        assert "site:target.com" in result
        assert "filetype:env" in result

    def test_login_pages_template(self):
        result = from_template("login_pages", domain="corp.io")
        assert "site:corp.io" in result
        assert "inurl:login" in result

    def test_subdomains_template(self):
        result = from_template("subdomains", domain="example.com")
        assert "site:*.example.com" in result
        assert "-www.example.com" in result

    def test_unknown_template_raises_valueerror(self):
        with pytest.raises(ValueError, match="Unknown template"):
            from_template("nonexistent_template", domain="x.com")

    def test_unknown_template_lists_available(self):
        with pytest.raises(ValueError) as exc_info:
            from_template("bad_name", domain="x.com")
        # Error message should include available templates
        assert "Available:" in str(exc_info.value)

    def test_missing_placeholder_raises_valueerror(self):
        with pytest.raises(ValueError, match="requires placeholder"):
            from_template("exposed_configs")  # missing 'domain'

    @pytest.mark.parametrize("template_name", get_template_names())
    def test_all_templates_render_with_domain(self, template_name):
        """All templates should render successfully with domain kwarg."""
        result = from_template(template_name, domain="test.com")
        assert isinstance(result, str)
        assert len(result) > 0


class TestTemplates:
    """Tests for templates dict and helper functions."""

    def test_templates_dict_not_empty(self):
        assert len(TEMPLATES) > 0

    def test_templates_count(self):
        assert len(TEMPLATES) == 12

    def test_get_template_names_returns_sorted(self):
        names = get_template_names()
        assert names == sorted(names)

    def test_get_template_names_has_all_keys(self):
        names = get_template_names()
        assert set(names) == set(TEMPLATES.keys())

    def test_get_template_info_returns_dict(self):
        info = get_template_info()
        assert isinstance(info, dict)
        assert len(info) == len(TEMPLATES)

    def test_get_template_info_values_are_strings(self):
        info = get_template_info()
        for name, template in info.items():
            assert isinstance(name, str)
            assert isinstance(template, str)

    @pytest.mark.parametrize("expected_template", [
        "exposed_configs", "login_pages", "directory_listing",
        "git_exposed", "env_files", "api_docs", "error_messages",
        "tech_stack", "database_dumps", "sensitive_docs",
        "subdomains", "backup_files",
    ])
    def test_expected_templates_exist(self, expected_template):
        assert expected_template in TEMPLATES

    def test_templates_contain_format_placeholders(self):
        """All templates should use {domain} placeholder."""
        for name, template in TEMPLATES.items():
            assert "{domain}" in template, f"Template '{name}' missing {{domain}}"
