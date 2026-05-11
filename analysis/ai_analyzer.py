"""
VulnIntel — AI Analyzer Module
Uses NVIDIA LLM API for intelligent vulnerability analysis and recommendations.
"""

import json
import logging
import requests
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

NVIDIA_API_BASE = "https://integrate.api.nvidia.com/v1"
NVIDIA_API_KEY = "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"
NVIDIA_MODEL = "meta/llama-3.1-70b-instruct"


class AIAnalyzer:
    """AI-powered vulnerability analysis using NVIDIA LLM."""

    def __init__(self, api_key: str = "", model: str = ""):
        self.api_key = api_key or NVIDIA_API_KEY
        self.model = model or NVIDIA_MODEL
        self.base_url = NVIDIA_API_BASE

    def _call_llm(self, system_prompt: str, user_prompt: str, max_tokens: int = 16384) -> str:
        """Call the NVIDIA LLM API with manual retries for 429 Rate Limits."""
        import time
        from openai import OpenAI, RateLimitError
        
        client = OpenAI(
            base_url="https://integrate.api.nvidia.com/v1",
            api_key=self.api_key,
            timeout=60.0,
            max_retries=1
        )

        max_attempts = 3
        for attempt in range(max_attempts):
            try:
                completion = client.chat.completions.create(
                    model="deepseek-ai/deepseek-v4-pro",
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    temperature=1,
                    top_p=0.95,
                    max_tokens=max_tokens,
                    extra_body={"chat_template_kwargs": {"thinking": False}},
                    stream=True
                )

                full_content = ""
                for chunk in completion:
                    if getattr(chunk, "choices", None) and chunk.choices and chunk.choices[0].delta.content is not None:
                        full_content += chunk.choices[0].delta.content

                if "<think>" in full_content and "</think>" in full_content:
                    full_content = full_content.split("</think>")[-1].strip()
                    
                return full_content
            except RateLimitError as e:
                logger.warning(f"AI API Rate Limited (429). Attempt {attempt + 1}/{max_attempts}. Sleeping...")
                if attempt < max_attempts - 1:
                    time.sleep(15 * (attempt + 1))  # Exponential backoff: 15s, 30s...
                else:
                    return f"[AI Error] Rate Limit Exceeded after 3 attempts: {str(e)}"
            except Exception as e:
                logger.error(f"AI API call failed: {e}")
                return f"[AI Error] {str(e)}"
        
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

        user_prompt = f"Prioritize these CVEs for defensive security research:\n\n" + "\n".join(cve_summaries)
        return self._call_llm(system_prompt, user_prompt, max_tokens=2000)

    def analyze_failed_exploit_search(self, cve_data: Dict[str, Any], queries: List[str]) -> str:
        """Analyze a CVE when no public exploits are found and suggest a theoretical approach."""
        cve_id = cve_data.get("cve_id", "Unknown")
        description = cve_data.get("description", "No description available")
        cvss_score = cve_data.get("cvss_score", "N/A")
        severity = cve_data.get("severity", "N/A")
        affected_products = cve_data.get("affected_products", [])
        affected_versions = cve_data.get("affected_versions", [])

        system_prompt = """You are an elite vulnerability researcher.
A search for public exploits for the given CVE has FAILED (no results found).
Your task is to:
1. Analyze the FULL CVE specifications and description to determine the likely vulnerability type (e.g., SQLi, RCE, XSS).
2. Write an actual custom Proof of Concept (PoC) python script or bash command that attempts to exploit this vulnerability in a lab environment. Wrap the code in markdown blocks.
3. Provide the exact bash commands needed to set up a vulnerable lab target (using Docker, apt, etc) and to execute the exploit you just wrote.
4. Provide a safe lab testing strategy to verify if the target is vulnerable.

Keep it highly technical. You MUST output actual bash commands and scripts that a security researcher can run immediately."""

        user_prompt = f"""Exploit Search Failed for: {cve_id}
Queries Attempted: {', '.join(queries)}

CVE Details & Specifications:
- CVSS Score: {cvss_score}
- Severity: {severity}
- Affected Products: {', '.join(affected_products) if affected_products else 'Unknown'}
- Affected Versions: {affected_versions}

CVE Description:
{description}

No public exploits were found. Please generate a custom technical analysis, a theoretical python exploit script, and exact bash commands to test this specific vulnerability using all the detailed specifications provided above."""

        return self._call_llm(system_prompt, user_prompt, max_tokens=3000)

    def is_available(self) -> bool:
        """Check if the AI API is reachable."""
        try:
            headers = {"Authorization": f"Bearer {self.api_key}"}
            resp = requests.get(f"{self.base_url}/models", headers=headers, timeout=10)
            return resp.status_code == 200
        except Exception:
            return False
