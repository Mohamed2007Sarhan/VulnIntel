# `config.py`

## المسار

`config.py` (جذر المشروع)

## الدور

مركز **الثوابت العامة**: مسارات، عناوين API، مفاتيح، ألوان الواجهة، سياسة السلامة، وفترات المزامنة.

## أهم المجموعات

| القسم | أمثلة |
|--------|--------|
| **مسارات** | `BASE_DIR`, `DATA_DIR`, `EXPORTS_DIR`, `DB_PATH` — يُنشأ `data/` و `exports/` عند الاستيراد. |
| **واجهات API** | `NVD_API_BASE`, `GITHUB_ADVISORIES_API`, `SPLOITUS_SEARCH_URL`. |
| **حدود المعدّل** | `NVD_*`, `GITHUB_RATE_LIMIT*`, `SPLOITUS_REQUEST_DELAY`, `AI_REQUEST_COOLDOWN_SECONDS`. |
| **Groq** | `GROQ_API_BASE`, `GROQ_MODEL`, `GROQ_MAX_OUTPUT_TOKENS`, `GROQ_PROMPT_DESCRIPTION_MAX_CHARS`, `GROQ_TPM_BACKOFF_SECONDS`, `GROQ_API_KEY` (من البيئة أو افتراضي في الكود). |
| **مفاتيح** | `NVD_API_KEY`, `GITHUB_PAT`, `GROQ_API_KEY`. |
| **مظهر الواجهة** | `APPEARANCE_MODE`, `COLOR_THEME`, قاموس `COLORS` (خلفيات، نصوص، حدود، ألوان الشدة، …). |
| **خريطة الشدة** | `SEVERITY_MAP` — لون وأيقونة ووزن لكل مستوى. |
| **نضج الاستغلال** | `EXPLOIT_MATURITY`. |
| **السلامة** | `SAFETY_POLICY`, `PRIVATE_NETWORK_RANGES`. |
| **المزامنة** | `DEFAULT_SYNC_INTERVAL`, `MAX_CVE_FETCH_LIMIT`, `DEFAULT_DAYS_LOOKBACK`. |
| **التطبيق** | `APP_NAME`, `APP_VERSION`, `WINDOW_SIZE`, `MIN_WINDOW_SIZE`. |

## من يستورد `config`؟

أغلب الوحدات: `gui/*`, `sources/*`, `analysis/ai_analyzer.py`, `database` غالبًا لا يستورد مباشرة لكن المسارات تمر عبر التطبيق.

## ملاحظة أمنية

المفاتيح الحساسة يُفضّل الإبقاء عليها في **متغيرات البيئة** وليس في الملف إذا كان المستودع عامًا.
