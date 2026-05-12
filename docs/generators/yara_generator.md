# `generators/yara_generator.py`

## الدور

توليد **قواعد YARA** للبحث عن أنماط/سلاسل مرتبطة بـ CVE.

## الدالة الرئيسية

`generate_yara_rule(cve, exploit=None) -> str`

- اسم القاعدة آمن من أحرف CVE.  
- `_build_strings` و `_build_condition` يبنيان قسم strings والشرط.

## الاستخدام

Pipeline في `gui/app.py` و `report_generator.py`.
