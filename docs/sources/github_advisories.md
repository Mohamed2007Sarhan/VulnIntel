# `sources/github_advisories.py`

## الدور

جلب **GitHub Security Advisories** من REST API (`GITHUB_ADVISORIES_API`).

## الفئة `GitHubAdvisoriesSource`

- رؤوس `Accept` وإصدار API؛ **Bearer** اختياري عبر `GITHUB_PAT` لرفع حد المعدّل.  
- `fetch_recent` / `search`: تحويل النتائج إلى CVEs موحّدة.

## في التطبيق

`self.sources["github"]` — تنبيه: الاسم **github** يخص الاستشارات الأمنية وليس بحث GitHub العام للاستغلال (الذي يُنفَّذ في `gui/app.py` عبر HTTP إلى `api.github.com/search/repositories`).
