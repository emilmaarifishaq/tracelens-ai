import json
import os
import re
import urllib.error
import urllib.request
from typing import Any


OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"
DEFAULT_MODEL = "gpt-4o"


def explain_trace_context(
    ai_context: dict,
    question: str = "",
    use_ai: bool = True,
    mask_identifiers: bool = True,
    api_key: str | None = None,
    model: str | None = None,
    web_search_enabled: bool | None = None,
    base_url: str | None = None,
    provider: str | None = None,
) -> dict:
    masked_context = mask_context(ai_context) if mask_identifiers else ai_context
    fallback = build_rule_based_explanation(masked_context, question)

    config = load_ai_config()

    if provider:
        config["provider"] = provider
        if not base_url:
            config["base_url"] = get_default_base_url(provider)
    if api_key:
        config["api_key"] = api_key
    if model:
        config["model"] = model
    if web_search_enabled is not None:
        config["web_search_enabled"] = web_search_enabled and config["provider"] == "openai"
    if base_url:
        config["base_url"] = base_url

    requires_api_key = config["provider"] not in {"rule-engine", "ollama"}

    # Check if user requested AI but API key is missing
    api_key_missing = requires_api_key and not config["api_key"]
    explicitly_disabled = not use_ai or config["provider"] == "rule-engine"

    if explicitly_disabled or api_key_missing:
        result = {
            **fallback,
            "provider": "rule-engine",
            "mode": "offline",
            "ai_used": False,
            "masked": mask_identifiers,
            "web_search_used": False,
        }

        # Add error message only when user requested AI but API key is missing
        if use_ai and api_key_missing:
            result["ai_error"] = f"API key required for {config['provider']} provider. Falling back to local rules. Add your API key in Settings to use AI-powered analysis."

        return result

    try:
        ai_text = call_ai_provider(masked_context, fallback, question, config)
    except RuntimeError as exc:
        return {
            **fallback,
            "provider": "rule-engine",
            "mode": "offline-fallback",
            "ai_used": False,
            "masked": mask_identifiers,
            "web_search_used": False,
            "ai_error": str(exc),
        }

    return {
        **fallback,
        "provider": config["provider"],
        "mode": "ai-web-assisted" if config["web_search_enabled"] else "ai-assisted",
        "ai_used": True,
        "masked": mask_identifiers,
        "web_search_used": config["web_search_enabled"],
        "ai_text": ai_text,
    }


def build_rule_based_explanation(ai_context: dict, question: str = "") -> dict:
    summary = ai_context.get("trace_summary", {})
    errors = ai_context.get("detected_errors", [])
    procedures = summary.get("procedures", [])
    timeline = summary.get("failure_timeline", [])
    drilldowns = summary.get("session_drilldowns", [])
    first_drilldown = drilldowns[0] if drilldowns else {}

    # Check if errors are grouped by cause code
    errors_by_cause_code = ai_context.get("errors_by_cause_code", {})
    unique_cause_codes = ai_context.get("unique_cause_codes", [])

    if errors:
        # If we have cause code grouping, generate explanations per cause code
        if unique_cause_codes and errors_by_cause_code:
            explanations_by_cause = {}
            for cause_code in unique_cause_codes[:5]:  # Limit to top 5 cause codes
                cause_errors = errors_by_cause_code.get(str(cause_code), [])
                if cause_errors:
                    first_cause_error = cause_errors[0]
                    evidence = []

                    # Add evidence from timeline related to this cause
                    for item in timeline[:3]:
                        evidence_text = item.get("evidence")
                        if evidence_text and evidence_text not in evidence:
                            evidence.append(str(evidence_text))

                    # Add evidence from errors with this cause code
                    for error in cause_errors[:3]:
                        evidence_text = str(error.get("evidence") or f"{error.get('protocol')} error at frame {error.get('frame')}")
                        if evidence_text not in evidence:
                            evidence.append(evidence_text)

                    actions = []
                    for error in cause_errors[:2]:
                        for action in error.get("recommended_checks", []):
                            if action not in actions:
                                actions.append(action)
                    if not actions and first_drilldown:
                        actions = first_drilldown.get("next_checks", [])

                    explanations_by_cause[cause_code] = {
                        "cause_code": cause_code,
                        "summary": (
                            f"{first_cause_error.get('error')} (Cause {cause_code}) occurred {len(cause_errors)} "
                            f"{pluralize('time', len(cause_errors))} across the trace."
                        ),
                        "root_cause": first_cause_error.get("root_cause") or "A protocol peer returned an explicit failure code.",
                        "confidence": "high",
                        "evidence": evidence[:5],
                        "recommended_actions": actions[:3],
                    }

            # Return main summary plus per-cause-code details
            return {
                "summary": (
                    f"TraceLens detected {len(errors)} explicit protocol {pluralize('issue', len(errors))} "
                    f"across {len(unique_cause_codes)} unique cause {pluralize('code', len(unique_cause_codes))}."
                ),
                "root_cause": "Multiple protocol issues detected",
                "confidence": "high",
                "evidence": [],
                "recommended_actions": [],
                "question": question,
                "explanations_by_cause_code": explanations_by_cause,
            }

        # Fallback to original behavior if no cause code grouping
        first_error = errors[0]
        evidence = []
        drilldown_evidence = first_drilldown.get("what_happened")
        if drilldown_evidence:
            evidence.append(str(drilldown_evidence))
        for item in timeline[:5]:
            evidence_text = item.get("evidence")
            if evidence_text and evidence_text not in evidence:
                evidence.append(str(evidence_text))
        for error in errors[:5]:
            evidence_text = str(error.get("evidence") or f"{error.get('protocol')} error at frame {error.get('frame')}")
            if evidence_text not in evidence:
                evidence.append(evidence_text)
        actions = []
        for action in first_drilldown.get("next_checks", []):
            if action not in actions:
                actions.append(action)
        for error in errors[:3]:
            for action in error.get("recommended_checks", []):
                if action not in actions:
                    actions.append(action)

        failed_procedures = [procedure for procedure in procedures if procedure.get("status") == "failed"]
        procedure_text = ""
        if failed_procedures:
            procedure = failed_procedures[0]
            duration = procedure.get("duration_ms")
            procedure_text = (
                f" The failed procedure is {procedure.get('procedure')} from frame "
                f"{procedure.get('request_frame')} to frame {procedure.get('response_frame')}"
                f"{f' with {duration} ms response time' if duration is not None else ''}."
            )

        notable_text = ""
        if timeline:
            first_notable = timeline[0]
            target = first_notable.get("url") or first_notable.get("host") or first_notable.get("message")
            notable_text = (
                f" First notable timeline event is {first_notable.get('reason')} at frame "
                f"{first_notable.get('frame')}{f' for {target}' if target else ''}."
            )

        return {
            "summary": (
                f"TraceLens detected {len(errors)} explicit protocol {pluralize('issue', len(errors))}. "
                f"The first issue is {first_error.get('error')} at frame {first_error.get('frame')}."
                f"{notable_text}{procedure_text}"
            ),
            "root_cause": first_error.get("root_cause") or "A protocol peer returned an explicit failure code.",
            "confidence": "high",
            "evidence": evidence[:8],
            "recommended_actions": actions,
            "question": question,
        }

    if timeline:
        first_notable = timeline[0]
        likely_cause = first_drilldown.get("likely_cause") or (
            "No explicit supported failure code was found, but the timeline shows behavior that should be reviewed."
        )
        actions = first_drilldown.get("next_checks") or [
            "Review the first notable timeline frame and the surrounding ladder events.",
            "Check the target host, redirect URL, status code, and DNS response for the same flow.",
            "Confirm whether the observed redirect or encrypted HTTPS destination is expected for this access scenario.",
        ]
        evidence = [str(item.get("evidence") or item.get("message")) for item in timeline[:8]]
        if first_drilldown.get("what_happened"):
            evidence.insert(0, str(first_drilldown["what_happened"]))
        return {
            "summary": (
                f"TraceLens decoded {summary.get('event_count', 0)} events and found notable flow behavior. "
                f"The first notable event is {first_notable.get('reason')} at frame {first_notable.get('frame')}."
            ),
            "root_cause": likely_cause,
            "confidence": "medium",
            "evidence": evidence[:8],
            "recommended_actions": actions,
            "question": question,
        }

    return {
        "summary": (
            f"TraceLens decoded {summary.get('event_count', 0)} events and did not detect an explicit supported "
            "protocol failure code."
        ),
        "root_cause": "No supported failure code was found in the decoded evidence.",
        "confidence": "low",
        "evidence": [],
        "recommended_actions": [
            "Review the ladder for missing responses or long procedure timing.",
            "Check whether the trace includes the complete interface path for the failed session.",
            "Add protocol-specific rules if the failure is visible in a field TraceLens does not evaluate yet.",
        ],
        "question": question,
    }


def load_ai_config() -> dict[str, Any]:
    provider = os.getenv("AI_PROVIDER", "").strip().lower()
    api_key = os.getenv("AI_API_KEY") or os.getenv("OPENAI_API_KEY") or ""
    if not provider:
        provider = "openai" if api_key else "rule-engine"

    model = os.getenv("AI_MODEL") or os.getenv("OPENAI_MODEL") or DEFAULT_MODEL
    base_url = os.getenv("AI_BASE_URL")
    web_search_enabled = env_bool("AI_WEB_SEARCH_ENABLED", False)

    if not base_url:
        base_url = get_default_base_url(provider)

    return {
        "provider": provider,
        "api_key": api_key,
        "model": model,
        "base_url": base_url,
        "web_search_enabled": web_search_enabled and provider == "openai",
    }


def get_default_base_url(provider: str) -> str:
    defaults = {
        "openai": "https://api.openai.com/v1/chat/completions",
        "claude": "https://api.anthropic.com/v1/messages",
        "azure": "https://YOUR_RESOURCE.openai.azure.com/v1/chat/completions",
        "ollama": "http://localhost:11434/api/chat",
        "gemini": "https://generativelanguage.googleapis.com/v1beta/models",
        "generic": "https://api.example.com/v1/chat/completions",
    }
    return defaults.get(provider, OPENAI_API_URL)


def build_request_url(provider: str, base_url: str, model: str) -> str:
    if provider == "gemini":
        # Gemini's model is part of the URL path, not the JSON body.
        return f"{base_url.rstrip('/')}/{model}:generateContent"
    return base_url


def call_ai_provider(ai_context: dict, fallback: dict, question: str, config: dict[str, Any]) -> str:
    provider = config["provider"]
    prompt_text = build_prompt(ai_context, fallback, question)
    system_prompt = (
        "You are a telecom 5G/LTE packet-trace troubleshooting expert. Your job is to provide INSIGHTS BEYOND the rule-based analysis.\n"
        "Go beyond confirming what errors exist - explain:\n"
        "1. WHY these specific causes occurred (network state, resource constraints, policy, timing)\n"
        "2. PATTERNS across cause codes - are they cascading failures, isolated issues, or systemic degradation?\n"
        "3. SEQUENCE IMPACT - how one failure triggered subsequent failures\n"
        "4. NETWORK CONTEXT - what these specific causes indicate about RAN, UE, or network slice state\n"
        "5. RECOVERY INDICATORS - what evidence would indicate the issue is resolved\n\n"
        "Cite frame numbers. Be concise and avoid repeating what the rule-engine already found. "
        "Focus on providing analysis depth that a tool cannot: pattern recognition, causality, and network state inference."
    )

    payload, headers = build_provider_request(provider, config["model"], system_prompt, prompt_text, config)
    request_url = build_request_url(provider, config["base_url"], config["model"])

    request = urllib.request.Request(
        request_url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            body = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"AI provider request failed: HTTP {exc.code} {detail[:300]}") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RuntimeError(f"AI provider request failed: {exc}") from exc

    return extract_provider_response(provider, body)


def build_provider_request(provider: str, model: str, system_prompt: str, prompt_text: str, config: dict[str, Any]) -> tuple[dict, dict]:
    headers = {
        "Content-Type": "application/json",
    }

    if provider == "openai":
        headers["Authorization"] = f"Bearer {config['api_key']}"
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt_text},
            ],
            "temperature": 0.7,
        }
        if config.get("web_search_enabled"):
            payload["tools"] = [{"type": "web_search"}]
    elif provider == "claude":
        headers["x-api-key"] = config["api_key"]
        headers["anthropic-version"] = "2023-06-01"
        payload = {
            "model": model,
            "max_tokens": 2048,
            "system": system_prompt,
            "messages": [
                {"role": "user", "content": prompt_text},
            ],
        }
    elif provider == "azure":
        headers["api-key"] = config["api_key"]
        payload = {
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt_text},
            ],
            "temperature": 0.7,
        }
    elif provider == "ollama":
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt_text},
            ],
            "stream": False,
        }
    elif provider == "gemini":
        headers["x-goog-api-key"] = config["api_key"]
        payload = {
            "contents": [
                {"role": "user", "parts": [{"text": prompt_text}]},
            ],
            "systemInstruction": {"parts": [{"text": system_prompt}]},
            "generationConfig": {"temperature": 0.7},
        }
    elif provider == "generic":
        headers["Authorization"] = f"Bearer {config['api_key']}"
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt_text},
            ],
        }
    else:
        headers["Authorization"] = f"Bearer {config['api_key']}"
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt_text},
            ],
        }

    return payload, headers


def extract_provider_response(provider: str, body: dict) -> str:
    if provider == "openai" or provider == "azure" or provider == "generic":
        if "choices" in body and len(body["choices"]) > 0:
            message = body["choices"][0].get("message", {})
            content = message.get("content")
            if isinstance(content, str) and content.strip():
                return content.strip()
    elif provider == "claude":
        if "content" in body and len(body["content"]) > 0:
            content_item = body["content"][0]
            if content_item.get("type") == "text":
                text = content_item.get("text")
                if isinstance(text, str) and text.strip():
                    return text.strip()
    elif provider == "ollama":
        message = body.get("message", {})
        content = message.get("content")
        if isinstance(content, str) and content.strip():
            return content.strip()
    elif provider == "gemini":
        candidates = body.get("candidates", [])
        if candidates:
            parts = candidates[0].get("content", {}).get("parts", [])
            if parts and isinstance(parts[0].get("text"), str) and parts[0]["text"].strip():
                return parts[0]["text"].strip()

    raise RuntimeError(f"AI provider {provider} response did not contain text output")


def env_bool(name: str, default: bool) -> bool:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    return raw_value.strip().lower() in {"1", "true", "yes", "on"}


def build_prompt(ai_context: dict, fallback: dict, question: str) -> str:
    detected_errors = ai_context.get("detected_errors", [])
    errors_by_cause = {}
    for error in detected_errors:
        cause = error.get("cause_code") or error.get("code") or "unknown"
        if cause not in errors_by_cause:
            errors_by_cause[cause] = []
        errors_by_cause[cause].append(error)

    return json.dumps(
        {
            "engineer_question": question or "Explain why these failures occurred, not just what they are. Focus on patterns, causality, and network state.",
            "trace_summary": {
                "total_events": ai_context.get("trace_summary", {}).get("event_count"),
                "unique_cause_codes": list(errors_by_cause.keys()),
                "cause_code_frequencies": {str(k): len(v) for k, v in errors_by_cause.items()},
            },
            "rule_engine_baseline": fallback,
            "detected_errors_by_cause": errors_by_cause,
            "trace_context": trim_ai_context_for_prompt(ai_context),
            "your_analysis_should_provide": [
                "Why these specific cause codes occurred (not just what they are)",
                "Patterns or cascading failures across the cause codes",
                "Network state inferences (RAN issues, UE limitations, policy, resources)",
                "Sequence of events and causality",
                "What would indicate recovery/resolution",
            ],
            "analysis_constraints": [
                "Cite frame numbers for key evidence",
                "Avoid repeating the rule-engine output",
                "Be concise - focus on insights, not exhaustive listing",
                "Only use evidence from the provided trace",
            ],
        },
        indent=2,
    )


def trim_ai_context_for_prompt(ai_context: dict) -> dict:
    """The AI's job here is to explain an already-detected failure, not to
    independently re-investigate the whole trace -- our own rule engine already
    computed root_cause and recommended_checks for every detected error. So the
    prompt only needs those errors (each one is already small and
    self-contained) plus a couple of counts for orientation; it does not need
    the rest of the trace structure (participants, procedures, procedure
    groups, protocol statistics, per-host session drilldowns, a sample of raw
    events, ...), all of which exist to power UI panels, not to re-derive a
    conclusion the rule engine already reached.

    For a real 33,055-frame capture this took the prompt from ~6,000,000 tokens
    (ai_context["events"] alone, uncapped) down to under 1,000."""
    trace_summary = ai_context.get("trace_summary", {})
    detected_errors = ai_context.get("detected_errors", [])[:10]

    minimal: dict = {
        "event_count": trace_summary.get("event_count"),
        "protocols_observed": trace_summary.get("protocols"),
        "detected_errors": detected_errors,
    }

    if not detected_errors:
        # No explicit rule-matched failure code -- the rule engine falls back to
        # timeline/drilldown evidence in this case (see build_rule_based_explanation),
        # so give the AI the same small amount of context, not the full structure.
        minimal["failure_timeline_sample"] = trace_summary.get("failure_timeline", [])[:5]
        session_drilldowns = trace_summary.get("session_drilldowns")
        if isinstance(session_drilldowns, list) and session_drilldowns:
            top_host = session_drilldowns[0]
            minimal["most_active_host"] = {
                "host": top_host.get("host"),
                "what_happened": top_host.get("what_happened"),
                "likely_cause": top_host.get("likely_cause"),
                "next_checks": top_host.get("next_checks"),
            }

    return minimal


def mask_context(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: mask_identifier(key, mask_context(child)) for key, child in value.items()}
    if isinstance(value, list):
        return [mask_context(item) for item in value]
    if isinstance(value, str):
        return mask_string(value)
    return value


def pluralize(word: str, count: int) -> str:
    return word if count == 1 else f"{word}s"


def mask_identifier(key: str, value: Any) -> Any:
    lowered = key.lower()
    if lowered in {"imsi", "msisdn", "imei", "supi", "gpsi"} and isinstance(value, str):
        return mask_digits(value)
    return value


def mask_string(value: str) -> str:
    masked = re.sub(r"\b\d{14,16}\b", lambda match: mask_digits(match.group(0)), value)
    masked = re.sub(r"\bimsi-\d{5,16}\b", lambda match: "imsi-" + mask_digits(match.group(0)[5:]), masked)
    return masked


def mask_digits(value: str) -> str:
    digits = re.sub(r"\D", "", value)
    if len(digits) <= 6:
        return "x" * len(digits)
    return f"{digits[:5]}{'x' * (len(digits) - 7)}{digits[-2:]}"
