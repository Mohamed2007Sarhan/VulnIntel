# `gui/dashboard_frame.py`

## الدور

إطار **لوحة التحكم**: نظرة عامة، مؤشرات KPI، CVEs حديثة، وسجل نصي للرسائل من الخيط الخلفي.

## الشكل (Layout)

1. **رأس**: عنوان "Dashboard"، على اليمين `StatusIndicator` ("Safety: ENFORCED") وساعة/وقت محدثة (`_update_time`).  
2. **بانر مراقبة**: إطار ملون بحد `accent_primary`، نقطة نابضة، نص "Continuous Monitoring Active" وسطر فرعي يذكر المصادر.  
3. **صف KPI**: بطاقات إحصائية من قاعدة البيانات (`refresh`).  
4. **عمودان**: يسار قائمة CVE حديثة كـ **`CVECard`**؛ يمين لوحة سجل (`CTkTextbox`) مع `append_log`.

## التفاعل

- النقر على بطاقة CVE يستدعي `on_cve_click(cve_data)` الممرَّر من `VulnIntelApp` للانتقال إلى CVE Browser.

## التبعيات

`config.COLORS`, `gui.components.cve_card.CVECard`, `gui.components.status_indicator.StatusIndicator`.
