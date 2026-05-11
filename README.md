# VulnIntel v2.0 - Defensive Vulnerability Intelligence Platform

![VulnIntel](https://img.shields.io/badge/Status-Active-success)
![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)

**VulnIntel** is an advanced, autonomous cybersecurity research platform designed for defensive teams. It continuously monitors vulnerability feeds, discovers exploit intelligence, leverages cutting-edge AI (NVIDIA DeepSeek) to generate custom Proof of Concepts (PoCs), and automatically builds detection rules to protect infrastructure.

---

## 🚀 Key Features

### 1. Autonomous Intelligence Pipeline
- **Continuous Monitoring:** Automatically fetches the latest CVEs from the **NVD** (National Vulnerability Database) and **GitHub Advisories**.
- **Public Exploit Scraping:** Automatically queries **Exploit-DB** and **Sploitus** for known public exploits. Found exploits are automatically downloaded and organized into the `data/public_exploits/` directory.

### 2. AI-Powered Exploit Generation
- **DeepSeek Integration:** When no public exploit exists, VulnIntel routes the full CVE specifications (CVSS, affected products, description) to NVIDIA's `deepseek-v4-pro` model.
- **Actionable PoCs:** The AI analyzes the vulnerability and generates actionable, custom Python scripts and bash commands to replicate the vulnerability in a safe lab environment.
- **File Persistence:** AI-generated scripts are securely saved as physical files in `data/ai_exploits/` for immediate testing.
- **Smart Retries & Backoff:** Built-in handling for `429 Too Many Requests` API rate limits, ensuring continuous background operations without hanging.

### 3. Automated Defense Generation (Sigma & YARA)
- Automatically analyzes attack vectors and keywords.
- Generates **Sigma rules** for SIEM/Log monitoring and **YARA rules** for malware/file scanning.
- Detection rules are saved directly to `data/detections/`.

### 4. Enterprise-Grade Architecture
- **Queue System & Fallbacks:** A resilient processing queue that automatically adjusts search terms (e.g., using truncated product names) if initial searches fail.
- **Database Rotation:** Built-in SQLite database rotation. Automatically archives the database and creates a fresh instance if it exceeds 50MB, guaranteeing optimal GUI performance over months of continuous use.
- **Beautiful GUI:** A premium, dark-mode graphical user interface built with `customtkinter`.

---

## 📂 Project Structure
```text
VulnIntel/
├── main.py                     # Entry point
├── config.py                   # Global configurations, API keys, and color themes
├── data/                       # Local storage (auto-generated)
│   ├── vulnintel.db            # SQLite Database
│   ├── ai_exploits/            # AI-generated PoC scripts
│   ├── public_exploits/        # Publicly scraped exploits
│   └── detections/             # Generated Sigma and YARA rules
├── gui/                        # UI Components (Dashboard, Queue, Public Search, etc.)
├── analysis/                   # AI integration and CVE analysis logic
├── generators/                 # Sigma and YARA rule generation logic
└── sources/                    # API wrappers (NVD, GitHub, Sploitus, ExploitDB)
```

---

## ⚙️ Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/VulnIntel.git
   cd VulnIntel
   ```

2. **Install dependencies:**
   ```bash
   pip install customtkinter openai requests
   ```

3. **Configure API Keys:**
   Open `config.py` (or set environment variables) and ensure you have valid API keys:
   - `NVIDIA_API_KEY`: Required for AI exploit generation (NVIDIA NIM).
   - `NVD_API_KEY`: (Optional but recommended) For higher rate limits on the NIST database.

4. **Run the application:**
   ```bash
   python main.py
   ```

---

## 🛡️ Safety & Defensive Policy
This tool is built strictly for **Defensive Security Research**. 
- All AI prompts are engineered to prioritize lab safety and authorized testing.
- The `config.py` enforces a strict `SAFETY_POLICY` block, preventing the generation of weaponized persistence or data exfiltration scripts.

---

## 📝 License
This project is licensed under the MIT License - see the LICENSE file for details.
