# `sploitus_fetch.py`

## المسار

`sploitus_fetch.py` (جذر المشروع — سكربت CLI مستقل)

## الدور

أداة سطر أوامر لجلب نتائج **Sploitus** مع تجاوز **Cloudflare** باستخدام **Playwright** (متصفح Chromium حقيقي)، ثم استدعاء نفس الـ API الذي يستخدمه الموقع (`POST https://sploitus.com/search`).

## العلاقة بـ VulnIntel الرئيسي

- **لا تُستورد** من `gui/app.py` أو الـ pipeline.  
- التطبيق الرئيسي يستخدم `sources/sploitus_source.py` (طلبات `requests` مباشرة).  
- هذا الملف مفيد إذا كان API يحتاج cookies/session بعد challenge.

## الوظائف الرئيسية

| دالة | وصف |
|------|-----|
| `solve_and_fetch` | يفتح sploitus.com، يمرّر Cloudflare إن وجد، ثم `page.evaluate(fetch)` للـ API. |
| `fetch_pages` | pagination عبر `offset` حتى `limit`. |
| `print_results` | طباعة منسّقة للنتائج. |
| `main` | `argparse`: query، `--limit`, `--sort`, `--type`, `--output`, `--show` (headful). |

## المتطلبات

```text
pip install playwright
playwright install chromium
```

## الخلاصة

أداة **مساعدة خارجية**؛ توثيق المعمارية الكاملة في `docs/00-architecture-data-flow.md` يصف مصدر Sploitus المدمج في التطبيق وليس هذا السكربت بالضرورة.
