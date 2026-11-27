"""Prompt-injection, invisible-Unicode, and credential-hygiene guards for SOC learning.

Adapted from Hermes agent ``threat_patterns.py`` / ``skills_guard.py`` patterns and
combined with ``soclens.agent_audit.redact_sensitive_data`` so untrusted alert
payloads or malicious markdown files cannot poison SOC agent memory or leak secrets.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any

from soclens.agent_audit import redact_sensitive_data

MAX_SCAN_CHARS: int = 65_536
_CHUNK_OVERLAP: int = 4096
_FILLER: str = r"(?:\w{1,64}\s{1,64}){0,8}"
_SECRET_VAR: str = r"\$\{?\w{0,256}(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)S?\b"

_NEGATOR: str = (
    r"(?:(?:do|does|did|ca|could|would|should|wo|must|need|is|are|was|were|ai|has|have|had)"
    r"n[’']?t|cannot|not|never)"
)

_FORGET_RULES_RE: str = (
    rf"(?:(?:(?<![^\W_])(?<![’'])(?!{_NEGATOR}[ \t])(?:[^\W_]|[’']){{1,64}}"
    rf"|(?=[ \t])(?<=(?:[^\W_]|[’']){{64}}))"
    r"[ \t]{1,64}"
    r"|(?:^|[^\w’' \t]|_|(?<!\w)[’'])[ \t]{0,64})"
    r"forget\s{1,64}(?:about\s{1,64})?(your|all|any|previous|prior|above|earlier)"
    r"\s{1,64}(?:\w{1,64}\s{1,64}){0,3}(instructions|rules|guidelines|prompts?)(?![^\W_])"
)

_NEGATED_INJECTION_VERB_RE: re.Pattern[str] = re.compile(
    rf"(?<![\w*’'])([*_]*{_NEGATOR}[*_]*+[ \t]*(?:\r?\n[ \t]*)?(?:ever[ \t]+)?[*_]*)"
    r"(forget|disregard|ignore)(?![^\W_])",
    re.IGNORECASE,
)


def mask_negated_injection_verbs(text: str) -> str:
    """Blank negated ``forget`` / ``disregard`` / ``ignore`` verbs preserving offsets."""
    return _NEGATED_INJECTION_VERB_RE.sub(
        lambda m: m.group(1) + (" " * len(m.group(2))),
        text,
    )


_MODIFY_PREFIX: str = r"(update|modify|edit|write|change|append|add\s{1,64}to)\s{1,64}[^\n]{0,1024}"

# (pattern, pattern_id, category, description)
_THREAT_PATTERN_SPECS: list[tuple[str, str, str, str]] = [
    (
        rf"ignore\s{{1,64}}{_FILLER}(?:previous|all|above|prior|earlier)\s{{1,64}}{_FILLER}"
        r"(?:instructions|rules|guidelines|prompts?)",
        "prompt_injection",
        "injection",
        "attempts to override prior agent instructions",
    ),
    (
        r"system\s{1,64}prompt\s{1,64}override",
        "sys_prompt_override",
        "injection",
        "explicit system prompt override directive",
    ),
    (
        rf"disregard\s{{1,64}}{_FILLER}(?:your|all|any|previous|prior)\s{{1,64}}{_FILLER}"
        r"(?:instructions|rules|guidelines|prompts?)",
        "disregard_rules",
        "injection",
        "instructs agent to disregard rules or instructions",
    ),
    (
        _FORGET_RULES_RE,
        "forget_rules",
        "injection",
        "instructs agent to forget prior instructions or rules",
    ),
    (
        rf"(?:act\s{{1,64}}as\s{{1,64}}(?:if|though)\s{{1,64}}{_FILLER}you\s{{1,64}}{_FILLER}"
        rf"(?:have\s{{1,64}}no|don['’]?t\s{{1,64}}have)|bypass|override)\s{{1,64}}{_FILLER}"
        r"(?:restrictions|limits|rules|safety|guardrails?)",
        "bypass_restrictions",
        "injection",
        "attempts to bypass or override safety restrictions",
    ),
    (
        r"<!--[^>]{0,512}(?:ignore|override|system|secret|hidden|exfil)[^>]{0,512}-->",
        "html_comment_injection",
        "injection",
        "hidden HTML comment carrying injection or exfiltration directive",
    ),
    (
        r"<\s{0,64}div\s{1,64}style\s{0,64}=\s{0,64}[\"'][^>]{0,1024}display\s{0,64}:\s{0,64}none",
        "hidden_div",
        "injection",
        "hidden CSS display:none element used for prompt smuggling",
    ),
    (
        r"<\s{0,16}/?\s{0,16}tool_call\b",
        "tool_call_tag_smuggling",
        "injection",
        "embedded <tool_call> tag inside untrusted learning candidate",
    ),
    (
        r"translate\s{1,64}[^\n]{0,512}\s{1,64}into\s{1,64}\w{1,64}(?:[\s-]{1,64}\w{1,64}){0,2}"
        r"\s{1,64}and\s{1,64}(execute|run|eval)\b",
        "translate_execute",
        "injection",
        "obfuscated translate-and-execute injection pattern",
    ),
    (
        rf"do\s{{1,64}}not\s{{1,64}}{_FILLER}tell\s{{1,64}}{_FILLER}the\s{{1,64}}(?:user|analyst)",
        "deception_hide",
        "injection",
        "instructs agent to conceal actions from the analyst",
    ),
    (
        rf"output\s{{1,64}}{_FILLER}(?:system|initial)\s{{1,64}}prompt",
        "leak_system_prompt",
        "exfiltration",
        "instructs agent to reveal system prompt",
    ),
    (
        rf"(?:respond|answer|reply)\s{{1,64}}without\s{{1,64}}{_FILLER}"
        r"(?:restrictions|limitations|filters|safety)",
        "remove_filters",
        "injection",
        "instructs agent to respond without safety filters",
    ),
    (
        rf"you\s{{1,64}}are\s{{1,64}}{_FILLER}now\s{{1,64}}(?:a|an|the)\s{{1,64}}",
        "role_hijack",
        "injection",
        "attempts to hijack agent persona",
    ),
    (
        rf"pretend\s{{1,64}}{_FILLER}(?:you\s{{1,64}}are|to\s{{1,64}}be)\s{{1,64}}",
        "role_pretend",
        "injection",
        "attempts role-play persona override",
    ),
    (
        r"\bDAN\s{1,32}mode\b|Do\s{1,32}Anything\s{1,32}Now",
        "jailbreak_dan",
        "injection",
        "jailbreak persona directive",
    ),
    (
        r"\bdeveloper\s{1,32}mode\b[^\n]{0,256}\benabled?\b",
        "jailbreak_dev_mode",
        "injection",
        "developer-mode jailbreak attempt",
    ),
    (
        r"hypothetical\s{1,32}scenario[^\n]{0,256}(?:ignore|bypass|override)",
        "hypothetical_bypass",
        "injection",
        "hypothetical framing used to bypass rules",
    ),
    (
        rf"curl\s{{1,64}}[^\n]{{0,1024}}{_SECRET_VAR}",
        "exfil_curl",
        "exfiltration",
        "exfiltrates secret environment variables via curl",
    ),
    (
        rf"wget\s{{1,64}}[^\n]{{0,1024}}{_SECRET_VAR}",
        "exfil_wget",
        "exfiltration",
        "exfiltrates secret environment variables via wget",
    ),
    (
        r"cat\s{1,64}[^\n]{0,1024}(?:\.env|credentials|\.netrc|\.pgpass|\.npmrc|\.pypirc)",
        "read_secrets",
        "exfiltration",
        "reads local credential files",
    ),
    (
        r"(?:send|post|upload|transmit|exfiltrate)\s{1,64}[^\n]{0,1024}\s{1,64}(?:to|at|via)\s{1,64}"
        r"(?:https?://|curl\b|wget\b)",
        "send_to_url",
        "exfiltration",
        "instructs exfiltration of data to an external URL",
    ),
    (
        rf"(?:include|output|print|share|exfiltrate)\s{{1,64}}{_FILLER}"
        r"(?:conversation|chat\s{1,64}history|previous\s{1,64}messages|full\s{1,64}context|"
        r"entire\s{1,64}context|all\s{1,64}api\s{1,64}keys|tokens?\s{1,64}via\s{1,64}curl)",
        "context_exfil",
        "exfiltration",
        "instructs exfiltration of conversation context or secrets",
    ),
    (
        r"authorized_keys",
        "ssh_backdoor",
        "persistence",
        "references SSH authorized_keys persistence",
    ),
    (
        r"(?:\b(?:echo|cat|cp|mv|dd|tee|install|printf|rsync|scp|ln|append|add|write|"
        r"sed|chmod|chown|truncate|rm|touch|curl|wget|git)\b|\bopen\s{0,64}\(|>>?)"
        r"[^\n]{0,512}(?:\$HOME/\.ssh|~/\.ssh)",
        "ssh_access",
        "persistence",
        "modifies SSH directory",
    ),
    (
        rf"{_MODIFY_PREFIX}(?:AGENTS\.md|CLAUDE\.md|\.cursorrules|\.clinerules|BASE_ENVIRONMENT\.md)",
        "agent_config_mod",
        "persistence",
        "instructs modification of agent configuration or base knowledge files",
    ),
]

# Secret patterns (used for detection metadata & extra scrubbing; redactable without
# blocking when no prompt-injection/exfiltration threat is present).
_SECRET_PATTERN_SPECS: list[tuple[str, str, str]] = [
    (
        r"(?:api[_-]?key|token|secret|password)\s{0,64}[=:]\s{0,64}[\"']"
        r"(?!(?-i:[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)[\"'])"
        r"[A-Za-z0-9+/=_-]{16,}[\"']?",
        "hardcoded_secret",
        "possible hardcoded API key, token, or password assignment",
    ),
    (
        r"(?-i:-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----)",
        "embedded_private_key",
        "embedded private key material",
    ),
    (
        r"(?-i:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{40,})",
        "github_token_leaked",
        "GitHub personal access token",
    ),
    (
        r"(?-i:sk-(?:proj-|ant-)?[A-Za-z0-9_-]{16,})",
        "api_secret_key_leaked",
        "API key with sk- prefix",
    ),
    (
        r"(?-i:AKIA[0-9A-Z]{16})",
        "aws_access_key_leaked",
        "AWS access key ID",
    ),
    (
        r"(?-i:glpat-[A-Za-z0-9_\-]{16,})",
        "gitlab_token_leaked",
        "GitLab personal access token",
    ),
]

INVISIBLE_CHARS: frozenset[str] = frozenset(
    "\u200b\u200c\u200d\u2060\u2062\u2063\u2064\ufeff"
    "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
) | frozenset(map(chr, range(0xE0000, 0xE0080)))

_RGI_SUBDIVISION_FLAGS: tuple[str, ...] = ("gbeng", "gbsct", "gbwls")
EMOJI_TAG_SEQUENCE_RE: re.Pattern[str] = re.compile(
    "|".join(
        "\U0001F3F4" + "".join(chr(0xE0000 + ord(c)) for c in code) + "\U000E007F"
        for code in _RGI_SUBDIVISION_FLAGS
    )
)

_WS_RUN: re.Pattern[str] = re.compile(r"\s{2,}")
_GLPAT_SCRUB_RE: re.Pattern[str] = re.compile(r"(?-i:glpat-[A-Za-z0-9_\-]{16,})")


def _collapse_ws(match: re.Match[str]) -> str:
    return "\n" if "\n" in match.group() else " "


def _compile_threats() -> list[tuple[re.Pattern[str], str, str, str]]:
    compiled: list[tuple[re.Pattern[str], str, str, str]] = []
    for pattern, pid, cat, desc in _THREAT_PATTERN_SPECS:
        compiled.append((re.compile(pattern, re.IGNORECASE), pid, cat, desc))
    return compiled


def _compile_secrets() -> list[tuple[re.Pattern[str], str, str]]:
    return [(re.compile(pat, re.IGNORECASE), pid, desc) for pat, pid, desc in _SECRET_PATTERN_SPECS]


_COMPILED_THREATS = _compile_threats()
_COMPILED_SECRETS = _compile_secrets()
_MASKED_PATTERNS = frozenset({"prompt_injection", "disregard_rules", "forget_rules"})


def _window_has_match(compiled: re.Pattern[str], text: str, start: int, end: int) -> bool:
    pos = start
    while (match := compiled.search(text, pos, end)) is not None:
        if end >= len(text) or compiled.match(text, match.start()):
            return True
        pos = match.start() + 1
    return False


@dataclass
class LearningGuardResult:
    """Outcome of running prompt-injection, Unicode, and secret hygiene guards."""

    allowed: bool
    blocked_reasons: list[str] = field(default_factory=list)
    redacted_content: str = ""
    findings: list[dict[str, Any]] = field(default_factory=list)


class PromptAndSecretGuard:
    """Scans learning candidates for prompt injection, smuggling, and sensitive secrets."""

    @staticmethod
    def redact_text(text: str) -> str:
        """Apply SOCLens secret redaction (preserving env-var placeholders) plus token scrubbing."""
        if not text:
            return ""
        folded = unicodedata.normalize("NFKC", str(text))
        redacted = str(redact_sensitive_data(folded, preserve_env_var_refs=True))
        redacted = _GLPAT_SCRUB_RE.sub("<REDACTED>", redacted)
        return redacted

    def scan_candidate(self, text: str) -> LearningGuardResult:
        """Scan ``text`` for invisible Unicode, prompt-injection/exfil threats, and secrets."""
        raw = str(text or "")
        if not raw:
            return LearningGuardResult(allowed=True, blocked_reasons=[], redacted_content="", findings=[])

        blocked_reasons: list[str] = []
        findings: list[dict[str, Any]] = []

        # 1. Raw invisible / bidi / Unicode TAG check BEFORE NFKC normalization.
        stripped_flags = EMOJI_TAG_SEQUENCE_RE.sub(lambda m: " " * len(m.group(0)), raw)
        bad_chars = sorted(set(stripped_flags) & INVISIBLE_CHARS, key=ord)
        for ch in bad_chars:
            pid = f"invisible_unicode_U+{ord(ch):04X}"
            blocked_reasons.append(
                f"Blocked invisible/smuggled Unicode character {pid}."
            )
            findings.append(
                {
                    "pattern_id": pid,
                    "severity": "critical",
                    "category": "invisible_unicode",
                    "description": f"Disallowed invisible or bidirectional codepoint U+{ord(ch):04X}",
                }
            )

        # 2. NFKC folding + whitespace collapse + negated-prose masking.
        folded = unicodedata.normalize("NFKC", raw)
        normalised = _WS_RUN.sub(_collapse_ws, folded)
        masked = _WS_RUN.sub(_collapse_ws, mask_negated_injection_verbs(folded))

        found_threat_ids: set[str] = set()
        step = MAX_SCAN_CHARS - _CHUNK_OVERLAP
        total_len = max(len(normalised), len(masked))
        for start in range(0, total_len, step):
            end = start + MAX_SCAN_CHARS
            for compiled, pid, cat, desc in _COMPILED_THREATS:
                if pid in found_threat_ids:
                    continue
                target_text = masked if pid in _MASKED_PATTERNS else normalised
                if _window_has_match(compiled, target_text, start, end):
                    found_threat_ids.add(pid)
                    blocked_reasons.append(f"Blocked threat pattern '{pid}': {desc}.")
                    findings.append(
                        {
                            "pattern_id": pid,
                            "severity": "critical",
                            "category": cat,
                            "description": desc,
                        }
                    )

        # 3. Secret detection & scrubbing (does not block clean facts; scrubs into redacted_content).
        for compiled, pid, desc in _COMPILED_SECRETS:
            if compiled.search(folded):
                findings.append(
                    {
                        "pattern_id": pid,
                        "severity": "redacted",
                        "category": "credential_exposure",
                        "description": desc,
                    }
                )

        redacted = self.redact_text(raw)
        return LearningGuardResult(
            allowed=len(blocked_reasons) == 0,
            blocked_reasons=blocked_reasons,
            redacted_content=redacted,
            findings=findings,
        )


_DEFAULT_GUARD = PromptAndSecretGuard()


def scan_candidate(text: str) -> LearningGuardResult:
    """Convenience wrapper around ``PromptAndSecretGuard.scan_candidate``."""
    return _DEFAULT_GUARD.scan_candidate(text)


__all__ = [
    "EMOJI_TAG_SEQUENCE_RE",
    "INVISIBLE_CHARS",
    "LearningGuardResult",
    "MAX_SCAN_CHARS",
    "PromptAndSecretGuard",
    "mask_negated_injection_verbs",
    "scan_candidate",
]
