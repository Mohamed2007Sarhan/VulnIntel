# `analysis/cve_analyzer.py`

## الدور

طبقة **إثراء CVE** فوق قاعدة البيانات: ربط الثغرات بالاستغلالات، تصنيف نضج الاستغلال، أولوية المخاطر، عدادات الاكتشافات ومختبر النتائج.

## الفئة: `CVEAnalyzer`

### `enrich_cve(cve_data)`

- يقرأ exploits من DB لذلك `cve_id`.  
- يحدّث الحقول المحسوبة: `exploit_maturity`, `has_public_exploit`, `exploit_count`, `risk_priority`, `detection_count`, `lab_test_count`.

### `get_full_analysis(cve_id)`

- يجمع CVE مثرى + exploits + references + detections + lab_results.

### `store_source_results(results)`

- لكل عنصر يحتوي `cve_id` صالح: `upsert_cve` وإضافة المراجع إلى `refs`.

### `store_exploit_results(exploits)`

- يضيف كل exploit إلى جدول `exploits`.

## التبعيات

- `database.db_manager.DatabaseManager`  
- `analysis.exploit_classifier` (`classify_exploit_maturity`, `calculate_risk_priority`)

## من يستدعيها؟

الـ pipeline في `gui/app.py`، إطارات الـ GUI التي تعرض التحليل، والـ queue.
