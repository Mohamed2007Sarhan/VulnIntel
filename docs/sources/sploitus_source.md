# `sources/sploitus_source.py`

## الدور

استعلام **Sploitus** عبر `POST https://sploitus.com/search` باستخدام `requests` + JSON.

## الفئة `SploitusSource`

- تأخير بين الطلبات (`SPLOITUS_REQUEST_DELAY`).  
- تحليل عناصر JSON إلى exploits مع `exploit_url` من الحقل `href`.

## ملاحظة

لسنا نستخدم هنا Playwright؛ السكربت المنفصل `sploitus_fetch.py` مخصص لحالات يحتاج فيها المتصفح لتجاوز حماية.

## في التطبيق

`self.sources["sploitus"]`.
