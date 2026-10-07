"""Tests for AI analysis provider fallback behavior (api_key validation)."""

import pytest
from app.services.ai_analysis import explain_trace_context


class TestAIAnalysisFallback:
    """Test API key missing fallback behavior."""

    def test_missing_api_key_shows_error_when_ai_requested(self):
        """When user requests AI but API key is missing, error message should be shown."""
        ai_context = {
            "trace_summary": {"event_count": 100},
            "detected_errors": [],
        }

        result = explain_trace_context(
            ai_context=ai_context,
            question="What happened?",
            use_ai=True,  # User explicitly requested AI
            provider="openai",  # Requires API key
            api_key=None,  # But no key provided
        )

        # Should fall back to rule-based
        assert result["ai_used"] is False
        assert result["provider"] == "rule-engine"

        # Should show error message
        assert "ai_error" in result
        assert "API key required" in result["ai_error"]
        assert "openai" in result["ai_error"].lower()

    def test_explicit_rule_engine_no_error(self):
        """When user explicitly selects rule-engine, no error should be shown."""
        ai_context = {
            "trace_summary": {"event_count": 100},
            "detected_errors": [],
        }

        result = explain_trace_context(
            ai_context=ai_context,
            question="What happened?",
            use_ai=True,
            provider="rule-engine",  # Explicitly using rule-engine
            api_key=None,
        )

        # Should use rule-based without error
        assert result["ai_used"] is False
        assert result["provider"] == "rule-engine"
        assert "ai_error" not in result  # No error message

    def test_use_ai_false_no_error(self):
        """When use_ai is False, no error should be shown."""
        ai_context = {
            "trace_summary": {"event_count": 100},
            "detected_errors": [],
        }

        result = explain_trace_context(
            ai_context=ai_context,
            question="What happened?",
            use_ai=False,  # Explicitly disabled
            provider="openai",
            api_key=None,
        )

        # Should fall back gracefully without error
        assert result["ai_used"] is False
        assert "ai_error" not in result

    def test_different_providers_error_message(self):
        """Error message should mention the specific provider."""
        ai_context = {
            "trace_summary": {"event_count": 100},
            "detected_errors": [],
        }

        for provider in ["openai", "claude", "gemini"]:
            result = explain_trace_context(
                ai_context=ai_context,
                question="What happened?",
                use_ai=True,
                provider=provider,
                api_key=None,
            )

            assert "ai_error" in result
            assert provider in result["ai_error"].lower()

    def test_ollama_no_error_when_api_key_missing(self):
        """Ollama doesn't require API key, so no error."""
        ai_context = {
            "trace_summary": {"event_count": 100},
            "detected_errors": [],
        }

        result = explain_trace_context(
            ai_context=ai_context,
            question="What happened?",
            use_ai=True,
            provider="ollama",  # Doesn't require API key
            api_key=None,
        )

        # Should attempt to use ollama (would fail at call_ai_provider if not running)
        # But key check should pass
        assert "API key required" not in result.get("ai_error", "")
