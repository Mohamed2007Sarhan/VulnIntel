# `gui/settings_frame.py`

## الدور

شاشة **الإعدادات**: مفاتيح API (NVD، GitHub PAT)، حفظ، وعرض سياسة السلامة من `SAFETY_POLICY`.

## الشكل

- عنوان كبير "Settings".  
- `CTkScrollableFrame` يحتوي أقسامًا:  
  - **API Keys**: حقول دخول مخفية (`show="•"`)، زر Save.  
  - **Safety Policy**: عرض القيم الحالية للسياسة (قراءة من config).

## `app_ref`

مرجع اختياري إلى `VulnIntelApp` إذا لزم ربط إعدادات بالتطبيق الحي.
