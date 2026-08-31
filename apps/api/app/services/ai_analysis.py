import json
import os
import re
import urllib.error
import urllib.request
from typing import Any


OPENAI_RESPONSES_URL = "https://api.openai.com/v1/responses"


def explain_trace_context(
    ai_context: dict,
    question: str = "",
    use_ai: bool = True,
    mask_identifiers: bool = True,
) -> dict:
    masked_context = mask_context(ai_context) if mask_identifiers else ai_context
    fallback = build_rule_based_explanation(masked_context, question)

    api_key = os.getenv("OPENAI_API_KEY")
    if not use_ai or not api_key:
        return {
            **fallback,
            "provider": "rule-engine",
            "mode": "offline",
            "ai_used": False,
            "masked": mask_identifiers,
        }

    try:
        ai_text = call_openai(masked_context, fallback, question, api_key)
    except RuntimeError as exc:
        return {
            **fallback,
            "provider": "rule-engine",
            "mode": "offline-fallback",
            "ai_used": False,
            "masked": mask_identifiers,
            "ai_error": str(exc),
        }

    return {
        **fallback,
        "provider": "openai",
        "mode": "ai-assisted",
        "ai_used": True,
        "masked": mask_identifiers,
        "ai_text": ai_text,
    }


def build_rule_based_explanation(ai_context: dict, question: str = "") -> dict:
    summary = ai_context.get("trace_summary", {})
    errors = ai_context.get("detected_errors", [])
    procedures = summary.get("procedures", [])

    if errors:
        first_error = errors[0]
        evidence = [
            str(error.get("evidence") or f"{error.get('protocol')} error at frame {error.get('frame')}")
            for error in errors[:5]
        ]
        actions = []
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

        return {
            "summary": (
                f"TraceLens detected {len(errors)} explicit protocol failure. "
                f"The first failure is {first_error.get('error')} at frame {first_error.get('frame')}."
                f"{procedure_text}"
            ),
            "root_cause": first_error.get("root_cause") or "A protocol peer returned an explicit failure code.",
            "confidence": "high",
            "evidence": evidence,
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


def call_openai(ai_context: dict, fallback: dict, question: str, api_key: str) -> str:
    model = os.getenv("OPENAI_MODEL", "gpt-5")
    payload = {
        "model": model,
        "instructions": (
            "You are a telecom packet-trace troubleshooting assistant. Explain only conclusions supported by "
            "the supplied decoded trace evidence. Cite frame numbers. If evidence is insufficient, say so."
        ),
        "input": build_prompt(ai_context, fallback, question),
    }
    request = urllib.request.Request(
        OPENAI_RESPONSES_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            body = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"OpenAI request failed: HTTP {exc.code} {detail[:300]}") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RuntimeError(f"OpenAI request failed: {exc}") from exc

    output_text = body.get("output_text")
    if isinstance(output_text, str) and output_text.strip():
        return output_text.strip()

    extracted = extract_response_text(body)
    if extracted:
        return extracted

    raise RuntimeError("OpenAI response did not contain text output")


def build_prompt(ai_context: dict, fallback: dict, question: str) -> str:
    return json.dumps(
        {
            "engineer_question": question or "Explain the trace failure and recommended troubleshooting actions.",
            "rule_engine_baseline": fallback,
            "trace_context": ai_context,
            "required_answer_style": {
                "include": ["failure point", "root cause", "evidence frames", "recommended checks", "confidence"],
                "avoid": ["unsupported guesses", "raw PCAP speculation"],
            },
        },
        indent=2,
    )


def extract_response_text(body: dict) -> str:
    parts = []
    for item in body.get("output", []):
        for content in item.get("content", []):
            text = content.get("text")
            if isinstance(text, str):
                parts.append(text)
    return "\n".join(parts).strip()


def mask_context(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: mask_identifier(key, mask_context(child)) for key, child in value.items()}
    if isinstance(value, list):
        return [mask_context(item) for item in value]
    if isinstance(value, str):
        return mask_string(value)
    return value


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
