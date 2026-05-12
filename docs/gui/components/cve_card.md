# `gui/components/cve_card.py`

## الدور

عنصر **`CVECard`**: بطاقة قابلة للنقر تعرض ملخص CVE.

## الشكل البصري

- إطار بزوايا دائرية، خلفية `bg_card`، حدود.  
- صف علوي: معرف CVE بخط Consolas ولون `accent_primary`.  
- على اليمين **حبة شدة** ملونة من `SEVERITY_MAP` (أيقونة + نص الشدة + CVSS).  
- وصف مختصر ~120 حرفًا.  
- مؤشر وجود exploit عام / نضج الاستغلال من `EXPLOIT_MATURITY`.

## التفاعل

- `cursor="hand2"`؛ نقرة تستدعي `on_click`.  
- `:hover` يغيّر لون الخلفية أو الحدود (`_on_enter` / `_on_leave`).
