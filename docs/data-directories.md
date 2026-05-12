# مجلدات البيانات تحت `data/` (مخرجات التطبيق)

هذه **ليست** ملفات مصدر للتطبيق؛ يُنشئها الـ pipeline أو المستخدم أثناء التشغيل.

| مسار | المصدر | المحتوى النموذجي |
|------|--------|-------------------|
| `data/vulnintel.db` | `DatabaseManager` | قاعدة SQLite الرئيسية. |
| `data/detections/` | مرحلة التوليد في `gui/app.py` | `{CVE}_sigma.yml`, `{CVE}_yara.yar`, `{CVE}_ioc.txt`. |
| `data/public_exploits/` | بحث Exploit-DB/Sploitus/GitHub | ملفات `.txt` مراجع أو كود مُنزَّل من روابط GitHub. |
| `data/ai_exploits/{CVE-ID}/` | `analyze_failed_exploit_search` بعد فشل البحث العام | `analysis.md`, PoC script, `detect.py`, أحيانًا `docker-compose.yml`. |

ملفات `.py` داخل `ai_exploits/` هي **مخرجات مُولَّدة**؛ أي تحديث للمنطق يكون في `analysis/ai_analyzer.py` و `gui/app.py` وليس يدويًا داخل هذه الملفات.
