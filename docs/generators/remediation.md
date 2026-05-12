# `generators/remediation.py`

## الدور

إنتاج **توصيات المعالجة** وهاردينغ بناءً على نوع الثغرة المذكورة في الوصف (SQLi، XSS، …) وحالة التصحيح.

## الدالة الرئيسية

`generate_remediation(cve) -> Dict`

يُرجع هيكلًا يحتوي `priority`, `steps`, `workarounds`, `hardening` حسب الكلمات المفتاحية في `description`.

## الاستخدام

تقارير أو واجهة توصيات عند ربطها من الإطارات المناسبة.
