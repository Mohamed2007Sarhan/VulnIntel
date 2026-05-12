"""
VulnIntel — AI Analyzer Module
Uses NVIDIA LLM API for intelligent vulnerability analysis and recommendations.
"""

import logging
import time
from typing import Dict, Any, List
from openai import OpenAI

logger = logging.getLogger(__name__)

NVIDIA_API_BASE = "https://integrate.api.nvidia.com/v1"
NVIDIA_API_KEY = "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"
NVIDIA_MODEL = "deepseek-ai/deepseek-v4-pro"


class AIAnalyzer:
    """AI-powered vulnerability analysis using NVIDIA LLM."""

    def __init__(self, api_key: str = "", model: str = ""):
        self.api_key = api_key or NVIDIA_API_KEY
        self.model = model or NVIDIA_MODEL
        self.client = OpenAI(
            base_url=NVIDIA_API_BASE,
            api_key=self.api_key
        )

    def _call_llm(self, system_prompt: str, user_prompt: str, max_tokens: int = 16384) -> str:
        """Call the NVIDIA LLM API with manual retries."""
        max_attempts = 3
        for attempt in range(max_attempts):
            try:
                completion = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    temperature=1,
                    top_p=0.95,
                    max_tokens=max_tokens,
                    stream=False
                )

                full_content = completion.choices[0].message.content or ""

                # Clean up reasoning tags if present
                if "<think>" in full_content and "</think>" in full_content:
                    full_content = full_content.split("</think>")[-1].strip()

                return full_content

            except Exception as e:
                error_str = str(e)
                logger.error(f"AI API call failed (attempt {attempt + 1}): {error_str}")

                if "429" in error_str:
                    if attempt < max_attempts - 1:
                        sleep_time = 45 * (attempt + 1)
                        logger.warning(f"Rate limited. Sleeping {sleep_time}s...")
                        time.sleep(sleep_time)
                        continue
                    return "[AI Error] Rate Limit Exceeded after 3 attempts."

                if attempt < max_attempts - 1:
                    time.sleep(10)
                else:
                    return f"[AI Error] {error_str}"

        return "[AI Error] Unknown failure"

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
        description = cve_data.get("description", "No description available")
        cvss_score = cve_data.get("cvss_score", "N/A")
        severity = cve_data.get("severity", "N/A")
        affected_products = cve_data.get("affected_products", [])
        affected_versions = cve_data.get("affected_versions", [])

        system_prompt = """You are an elite vulnerability researcher helping with authorized lab research.
When no public exploits exist for a CVE, analyze the description and provide:
1. The likely vulnerability type and attack surface
2. A theoretical PoC approach for lab testing
3. Docker/VM setup commands to create a safe test environment
4. Detection and remediation guidance

FORMAT INSTRUCTIONS:
Return the result as a raw JSON object (do not wrap it in markdown block quotes like ```json) with the following structure:
{
  "poc_script_filename": "exploit.py",  // Determine the best extension based on the exploit logic (e.g., .py, .php, .js)
  "poc_script_content": "import requests\n...", // The actual PoC code
  "docker_compose_content": "version: '3'\n...", // (Optional) Docker Compose file content for lab testing. Leave empty string if none.
  "analysis_markdown": "# Technical Analysis\n..." // The rest of your analysis, explanation, and detection guidance in Markdown format.
}"""

        user_prompt = f"""Exploit Search Failed for: {cve_id}
Queries Attempted: {', '.join(queries)}

CVE Details:
- CVSS Score: {cvss_score}
- Severity: {severity}
- Affected Products: {', '.join(affected_products) if affected_products else 'Unknown'}
- Affected Versions: {affected_versions}

CVE Description:
{description}

Provide a technical analysis and safe lab testing approach for this vulnerability. Ensure your output is purely the JSON format requested, without any surrounding markdown blocks."""

        return self._call_llm(system_prompt, user_prompt, max_tokens=8192)

    def is_available(self) -> bool:
        """Check if the AI API is reachable."""
        try:
            self.client.models.list()
            return True
        except Exception:
            return False