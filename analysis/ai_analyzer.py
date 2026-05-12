"""
VulnIntel — AI Analyzer Module
Uses Groq OpenAI-compatible API for vulnerability analysis and recommendations.
"""

import logging
import time
from typing import Dict, Any, List
from openai import OpenAI

from config import (
    AI_REQUEST_COOLDOWN_SECONDS,
    GROQ_API_BASE,
    GROQ_API_KEY,
    GROQ_MAX_OUTPUT_TOKENS,
    GROQ_MODEL,
    GROQ_PROMPT_DESCRIPTION_MAX_CHARS,
    GROQ_TPM_BACKOFF_SECONDS,
)

logger = logging.getLogger(__name__)


def _truncate_text(text: str, max_chars: int) -> str:
    if not text or max_chars <= 0:
        return text or ""
    text = str(text)
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 24].rstrip() + "\n...[truncated]"


class AIAnalyzer:
    """AI-powered vulnerability analysis via Groq.

    Each public method sends a single stateless chat completion (system + user only).
    There is no conversation memory between CVEs or between calls.
    """

    def __init__(self, api_key: str = "", model: str = "", request_cooldown_seconds: float = 0.0):
        self.api_key = api_key or GROQ_API_KEY
        self.model = model or GROQ_MODEL
        self._request_cooldown = float(request_cooldown_seconds or AI_REQUEST_COOLDOWN_SECONDS)
        self._last_ai_call_end = 0.0
        self.client = OpenAI(
            base_url=GROQ_API_BASE,
            api_key=self.api_key,
        )

    def _throttle_before_llm(self) -> None:
        """Sleep so consecutive API calls stay at least `_request_cooldown` apart."""
        if self._request_cooldown <= 0:
            return
        now = time.monotonic()
        elapsed = now - self._last_ai_call_end
        if self._last_ai_call_end > 0 and elapsed < self._request_cooldown:
            wait = self._request_cooldown - elapsed
            logger.debug("AI cooldown: sleeping %.2fs before next request", wait)
            time.sleep(wait)

    def _mark_llm_call_finished(self) -> None:
        self._last_ai_call_end = time.monotonic()

    @staticmethod
    def _groq_payload_or_tpm_error(error_str: str) -> bool:
        """413 / payload too large / TPM-style limits from Groq."""
        s = error_str.lower()
        return (
            "413" in error_str
            or "payload too large" in s
            or "request too large" in s
            or ("too large" in s and "token" in s)
            or ("limit 8000" in s and "requested" in s)
        )

    def _call_llm(self, system_prompt: str, user_prompt: str, max_tokens: int = 4096) -> str:
        """Call Groq chat completions — stateless, no prior CVE context."""
        max_tokens = min(int(max_tokens), GROQ_MAX_OUTPUT_TOKENS)
        max_attempts = 3
        last_error = ""
        floor_mt = min(512, max(128, max_tokens // 4))

        for attempt in range(max_attempts):
            self._throttle_before_llm()
            mt = max(max_tokens // (2 ** attempt), floor_mt)

            while mt >= floor_mt:
                try:
                    completion = self.client.chat.completions.create(
                        model=self.model,
                        messages=[
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_prompt},
                        ],
                        temperature=0.7,
                        top_p=0.95,
                        max_tokens=mt,
                        stream=False,
                    )

                    full_content = completion.choices[0].message.content or ""

                    if "<think>" in full_content and "</think>" in full_content:
                        full_content = full_content.split("</think>")[-1].strip()

                    self._mark_llm_call_finished()
                    return full_content

                except Exception as e:
                    error_str = str(e)
                    last_error = error_str
                    logger.error(f"AI API call failed (attempt {attempt + 1}, max_tokens={mt}): {error_str}")

                    if self._groq_payload_or_tpm_error(error_str):
                        if mt > floor_mt:
                            mt = max(floor_mt, mt // 2)
                            logger.warning(
                                "Groq payload/TPM limit; waiting %.0fs then retrying with max_tokens=%s",
                                GROQ_TPM_BACKOFF_SECONDS,
                                mt,
                            )
                            time.sleep(GROQ_TPM_BACKOFF_SECONDS)
                            continue
                        logger.warning(
                            "Groq TPM/payload still exceeded at min max_tokens=%s; waiting %.0fs before outer retry",
                            floor_mt,
                            GROQ_TPM_BACKOFF_SECONDS,
                        )
                        time.sleep(GROQ_TPM_BACKOFF_SECONDS)
                        self._mark_llm_call_finished()
                        break

                    if "429" in error_str:
                        if attempt < max_attempts - 1:
                            sleep_time = 45 * (attempt + 1)
                            logger.warning(f"Rate limited. Sleeping {sleep_time}s...")
                            time.sleep(sleep_time)
                            self._mark_llm_call_finished()
                            break
                        self._mark_llm_call_finished()
                        return "[AI Error] Rate Limit Exceeded after 3 attempts."

                    self._mark_llm_call_finished()
                    if attempt < max_attempts - 1:
                        time.sleep(10)
                        break

                    return f"[AI Error] {error_str}"

            self._mark_llm_call_finished()

        return f"[AI Error] {last_error}" if last_error else "[AI Error] Unknown failure"

    def analyze_target(self, target_info: Dict[str, Any]) -> str:
        """Analyze a target/application and recommend security approach."""
        system_prompt = """You are a defensive cybersecurity research assistant. 
You analyze software/targets for known vulnerabilities and recommend safe lab testing approaches.
You ONLY work within authorized lab environments (VulnLab, HackTheBox, Docker labs, local VMs, CTFs).
You NEVER recommend attacking real systems, stealing credentials, or deploying malware.
Provide analysis in clear markdown format with sections:
1. Target Overview
2. Potential Vulnerability Categories
3. Recommended CVEs to Investigate
4. Safe Lab Testing Strategy
5. Detection Recommendations
Always emphasize defensive security and authorized testing only."""

        user_prompt = f"""Analyze the following target for vulnerability research in an authorized lab:

Target Name: {target_info.get('name', 'Unknown')}
Target Type: {target_info.get('type', 'Unknown')}
Operating System: {target_info.get('os', 'Unknown')}
Services/Software: {target_info.get('services', 'Unknown')}
Version: {target_info.get('version', 'Unknown')}
Description: {target_info.get('description', 'No description provided')}

Provide a detailed security analysis with recommended CVEs, vulnerability categories, and safe lab testing approach."""

        return self._call_llm(system_prompt, user_prompt, max_tokens=3000)

    def analyze_cve(self, cve_data: Dict[str, Any]) -> str:
        """Provide AI-powered analysis of a specific CVE."""
        system_prompt = """You are a CVE analysis expert. Analyze the given vulnerability and provide:
1. Plain-language explanation of what the vulnerability does
2. Exploitation requirements and prerequisites
3. Impact assessment
4. Safe detection strategies
5. Remediation recommendations
Keep the analysis concise and actionable. Only recommend lab-safe testing approaches."""

        user_prompt = f"""Analyze this CVE:

CVE ID: {cve_data.get('cve_id', 'Unknown')}
CVSS Score: {cve_data.get('cvss_score', 'N/A')}
Severity: {cve_data.get('severity', 'N/A')}
Description: {cve_data.get('description', 'No description')}
Affected Products: {cve_data.get('affected_products', 'Unknown')}
Has Public Exploit: {cve_data.get('has_public_exploit', False)}
Exploit Maturity: {cve_data.get('exploit_maturity', 'none')}"""

        return self._call_llm(system_prompt, user_prompt, max_tokens=2000)

    def recommend_priority(self, cves: List[Dict[str, Any]]) -> str:
        """Analyze a batch of CVEs and recommend processing priority order."""
        system_prompt = """You are a vulnerability prioritization expert.
Given a list of CVEs, rank them by priority for defensive security research.
Consider: CVSS score, exploit availability, affected product criticality, and patch status.
Output a numbered priority list with brief justification for each ranking.
Focus on defensive value — which vulnerabilities need detection rules and lab validation first?"""

        cve_summaries = []
        for i, cve in enumerate(cves[:20], 1):
            cve_summaries.append(
                f"{i}. {cve.get('cve_id', 'N/A')} | CVSS: {cve.get('cvss_score', 0)} | "
                f"Severity: {cve.get('severity', 'NONE')} | "
                f"Exploit: {'Yes' if cve.get('has_public_exploit') else 'No'} | "
                f"Desc: {(cve.get('description', '') or '')[:100]}"
            )

        user_prompt = "Prioritize these CVEs for defensive security research:\n\n" + "\n".join(cve_summaries)
        return self._call_llm(system_prompt, user_prompt, max_tokens=2000)

    def analyze_failed_exploit_search(self, cve_data: Dict[str, Any], queries: List[str]) -> str:
        """Analyze a CVE when no public exploits are found and suggest a theoretical approach."""
        cve_id = cve_data.get("cve_id", "Unknown")
        description = _truncate_text(
            str(cve_data.get("description", "No description available")),
            GROQ_PROMPT_DESCRIPTION_MAX_CHARS,
        )
        cvss_score = cve_data.get("cvss_score", "N/A")
        severity = cve_data.get("severity", "N/A")
        affected_products = cve_data.get("affected_products", [])
        affected_versions = cve_data.get("affected_versions", [])

        queries_joined = _truncate_text(", ".join(str(q) for q in (queries or [])[:30]), 1400)

        system_prompt = """You are an elite vulnerability researcher helping with authorized lab research.
When no public exploits exist for a CVE, analyze the description and provide:
1. The likely vulnerability type and attack surface
2. A theoretical PoC approach for lab testing
3. Docker/VM setup commands to create a safe test environment
4. Detection and remediation guidance

Keep poc_script_content and detect_script_content SHORT (minimal lab PoC). Put depth in analysis_markdown.

FORMAT INSTRUCTIONS:
Return the result as a raw JSON object (do not wrap it in markdown block quotes like ```json) with the following structure:
{
  "poc_script_filename": "exploit.py",  // Determine the best extension based on the exploit logic (e.g., .py, .php, .js)
  "poc_script_content": "import requests\n...", // The actual PoC code
  "detect_script_filename": "detect.py", // A Python detection script that checks a target (IP/domain/URL/host/app identifier/MAC text) for signs of this CVE.
  "detect_script_content": "import socket\n...", // Script must accept a target argument and print whether the CVE appears present and where.
  "docker_compose_content": "version: '3'\n...", // (Optional) Docker Compose file content for lab testing. Leave empty string if none.
  "analysis_markdown": "# Technical Analysis\n..." // The rest of your analysis, explanation, and detection guidance in Markdown format.
}"""

        user_prompt = f"""Exploit Search Failed for: {cve_id}
Queries Attempted: {queries_joined}

CVE Details:
- CVSS Score: {cvss_score}
- Severity: {severity}
- Affected Products: {', '.join(affected_products) if affected_products else 'Unknown'}
- Affected Versions: {affected_versions}

CVE Description:
{description}

Provide a technical analysis and safe lab testing approach for this vulnerability. Ensure your output is purely the JSON format requested, without any surrounding markdown blocks."""

        return self._call_llm(system_prompt, user_prompt, max_tokens=min(3072, GROQ_MAX_OUTPUT_TOKENS))

    def choose_best_exploit_candidate(self, cve_data: Dict[str, Any], candidates: List[Dict[str, Any]]) -> str:
        """Choose the best exploit candidate from public search results."""
        cve_id = cve_data.get("cve_id", "Unknown")
        description = cve_data.get("description", "No description available")

        condensed = []
        for idx, item in enumerate(candidates[:15], 1):
            condensed.append(
                f"{idx}. title={item.get('exploit_title', '')}\n"
                f"   source={item.get('exploit_source', '')}\n"
                f"   url={item.get('exploit_url', '')}\n"
                f"   description={item.get('description', '')[:220]}"
            )

        system_prompt = """You are a defensive vulnerability analyst.
Select the single best public exploit candidate for authorized lab validation.
Prioritize: direct CVE match, technical relevance, PoC quality signals, trusted source.

Return only raw JSON in this exact structure:
{
  "selected_index": 1,
  "confidence": 0.0,
  "reason": "short reason"
}"""

        user_prompt = f"""CVE ID: {cve_id}
CVE Description: {_truncate_text(str(description), 1600)}

Candidates:
{chr(10).join(condensed)}

Pick exactly one best candidate. selected_index is 1-based from the list."""

        return self._call_llm(system_prompt, user_prompt, max_tokens=800)

    def generate_exploit_search_queries(self, cve_data: Dict[str, Any]) -> str:
        """Generate smart exploit search queries for public sources."""
        cve_id = cve_data.get("cve_id", "Unknown")
        description = cve_data.get("description", "")
        affected_products = cve_data.get("affected_products", "")
        affected_versions = cve_data.get("affected_versions", "")

        system_prompt = """You help generate exploit discovery queries for authorized lab research.
Return ONLY raw JSON in this exact shape:
{
  "queries": ["query 1", "query 2", "query 3", "query 4", "query 5"]
}
Rules:
- Include the CVE ID in at least one query.
- Prefer product + version + exploit terms.
- Keep each query short and practical for ExploitDB/Sploitus/GitHub searches.
- Max 8 queries."""

        user_prompt = f"""Generate practical exploit search queries for:
CVE ID: {cve_id}
Description: {_truncate_text(str(description), 2200)}
Affected Products: {_truncate_text(str(affected_products), 400)}
Affected Versions: {_truncate_text(str(affected_versions), 400)}"""

        return self._call_llm(system_prompt, user_prompt, max_tokens=600)

    def is_available(self) -> bool:
        """Check if the AI API is reachable."""
        try:
            self.client.models.list()
            return True
        except Exception:
            return False