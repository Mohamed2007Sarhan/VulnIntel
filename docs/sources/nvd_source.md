# `sources/nvd_source.py`

## الدور

جلب بيانات من **NIST NVD API 2.0** (`NVD_API_BASE`).

## الفئة `NVDSource`

- يحترم **حد المعدّل** (`NVD_RATE_LIMIT_*`, `NVD_RATE_WINDOW`) مع/بدون مفتاح.  
- `fetch_recent`: CVEs ضمن نافذة زمنية.  
- `search`: بحث حسب المعايير المدعومة من API.  
- تحويل استجابة JSON إلى قواميس CVE متوافقة مع `CVEAnalyzer.store_source_results`.

## تكامل التطبيق

مسجّل في `gui/app.py` ضمن `self.sources["nvd"]`.
