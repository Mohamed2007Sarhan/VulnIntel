# `database/models.py`

## الدور

1. تعريف **مخطط SQLite** كنص `SCHEMA_SQL`: الجداول `cves`, `exploits`, `lab_results`, `refs`, `detections`, `lab_targets` والفهارس.  
2. **`init_database(db_path)`**: إنشاء مجلد القاعدة، اتصال `sqlite3` مع `check_same_thread=False`، `Row` factory، **WAL**، تفعيل المفاتيح الأجنبية، تنفيذ السكربت.

## الجداول (ملخص)

| الجدول | وصف مختصر |
|--------|-----------|
| `cves` | الهوية الفريدة `cve_id`، الوصف، CVSS، الشدة، منتجات/إصدارات JSON، نضج الاستغلال، تواريخ، مصدر، raw_data. |
| `exploits` | مرتبط بـ `cve_id`: عنوان، مصدر، رابط، نوع، منصة، وصف، أمان المختبر، workflow JSON. |
| `lab_results` | نتائج تشغيل في مختبر لـ CVE/exploit. |
| `refs` | مراجع خارجية (روابط). |
| `detections` | قواعد sigma/yara/ioc أو محتوى نصي. |
| `lab_targets` | سجل أهداف مختبر معروفة. |

## من يستدعي `init_database`؟

`VulnIntelApp.__init__` في `gui/app.py` يمرّر `DB_PATH` من `config`.
