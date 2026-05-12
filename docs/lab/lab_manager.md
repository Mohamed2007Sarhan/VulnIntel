# `lab/lab_manager.py`

## الدور

إدارة **أهداف المختبر** المصرّح بها وتسجيل نتائج التشغيل.

## الفئة `LabManager`

| طريقة | وظيفة |
|--------|--------|
| `register_target` | يتحقق عبر `validate_target` من `safety_policy` ثم `add_lab_target` في DB. |
| `get_targets` / `remove_target` | قائمة وحذف الأهداف. |
| `is_authorized_target` | مطابقة IP مع الجدول. |
| `record_result` | كتابة صف في `lab_results`. |

## التبعيات

`DatabaseManager`, `analysis.safety_policy`

## الواجهة

`gui/lab_frame.py` يستخدم `LabManager`.
