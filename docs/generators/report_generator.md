# `generators/report_generator.py`

## الدور

بناء **تقرير Markdown شامل** لـ CVE واحد: ملخص تنفيذي، أقسام للاستغلالات، المراجع، قواعد مضمنة (Sigma/YARA/IOC من المولدات)، نتائج مختبر إن وُجدت.

## الدالة الرئيسية

`generate_full_report(cve, exploits, references, detections, lab_results) -> str`

يستورد `generate_sigma_rule`, `generate_yara_rule`, `generate_ioc_summary`, `format_ioc_text` لدمج المحتوى في التقرير.

## الاستخدام

إطار **Reports** في الواجهة (`gui/reports_frame.py`) أو أي مسار يستدعي التوليد.
