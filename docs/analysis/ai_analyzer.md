# `analysis/ai_analyzer.py`

## الدور

طبقة **Groq LLM** عبر عميل OpenAI متوافق (`OpenAI` من مكتبة `openai` مع `base_url = GROQ_API_BASE`). كل استدعاء **لا يحمل سياق محادثات سابقة**؛ رسالة `system` + `user` فقط.

## الفئة: `AIAnalyzer`

### التهيئة

- `api_key`, `model`: افتراضيًا من `config` (`GROQ_API_KEY`, `GROQ_MODEL`).  
- **Cooldown** بين الطلبات: `AI_REQUEST_COOLDOWN_SECONDS`.  
- `_throttle_before_llm()` يمنع إطلاق طلبات متتالية أسرع من الحد.

### `_call_llm`

- يحدّ `max_tokens` بـ `GROQ_MAX_OUTPUT_TOKENS`.  
- **إعادة محاولة** عند أخطاء حجم/TPM (413): تخفيض `max_tokens` تدريجيًا + `GROQ_TPM_BACKOFF_SECONDS`.  
- **429**: انتظار متزايد حتى 3 محاولات.  
- `temperature=0.7` تقريبًا.

### الدوال العمومية

| دالة | غرض |
|------|-----|
| `analyze_target` | تحليل هدف/تطبيق دفاعي. |
| `analyze_cve` | شرح CVE. |
| `recommend_priority` | ترتيب أولويات قائمة CVEs. |
| `analyze_failed_exploit_search` | عند فشل البحث عن exploits: JSON يحتوي PoC + detect + docker + markdown. **وصف CVE مقطوع** بحد `GROQ_PROMPT_DESCRIPTION_MAX_CHARS`. |
| `choose_best_exploit_candidate` | اختيار أفضل مرشح exploit من قائمة. |
| `generate_exploit_search_queries` | توليد استعلامات بحث ذكية. |
| `is_available` | `client.models.list()` للتحقق من الاتصال. |

## مساعد

`_truncate_text` — قص النص مع لاحقة `...[truncated]`.

## من يستدعيها؟

`gui/app.py` (pipeline)، `gui/public_search_frame.py`, `gui/target_analysis_frame.py`, `gui/queue_frame.py`, وغيرها التي تمرّر `ai_analyzer`.
