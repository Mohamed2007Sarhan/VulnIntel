# `generators/sigma_generator.py`

## الدور

توليد **قواعد Sigma** (YAML) من سجل CVE (واختياريًا exploit).

## الدالة الرئيسية

`generate_sigma_rule(cve, exploit=None) -> str`

- يستخرج `cve_id`, الوصف المختصر، الشدة، CVSS.  
- يحدّد `logsource` و `detection` عبر `_infer_detection`.  
- يضيف وسوم MITRE عبر `_infer_attack_tags`.  
- يُخرج نصًا كاملًا لملف `.yml`.

## الاستخدام

يُستدعى من `gui/app.py` في مرحلة التوليد التلقائي، ومن `report_generator.py`.
