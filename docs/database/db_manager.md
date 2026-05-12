# `database/db_manager.py`

## الدور

طبقة **CRUD** فوق اتصال SQLite واحد (`DatabaseManager(conn)`).

## عمليات CVE

- `upsert_cve` — INSERT أو UPDATE عند تعارض `cve_id`.  
- `get_cve`, `search_cves`, `get_all_cves`, … (حسب التطبيق الكامل في الملف).

## عمليات Exploits / Refs / Detections / Lab

دوال مثل `add_exploit`, `get_exploits_for_cve`, `add_reference`, `get_references`, `add_detection`, `get_detections_for_cve`, `get_lab_results`, إلخ — كلها تُرجع قواميس أو قوائم متوافقة مع واجهات الـ GUI.

## ملاحظة

استخدام `json.dumps` للحقول المخزنة كنص JSON في المخطط (`affected_products`, …).

## من يستخدمها؟

كل الإطارات التي تقرأ/تكتب البيانات، والـ pipeline في `gui/app.py`.
