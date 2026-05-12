# `analysis/safety_policy.py`

## الدور

تطبيق **سياسة السلامة** من `config.SAFETY_POLICY` و `PRIVATE_NETWORK_RANGES`:

- أنماط خطرة في النصوص (`DANGEROUS_PATTERNS`, `PERSISTENCE_PATTERNS`).  
- التحقق من أن الهدف في شبكة خاصة / مختبر مسموح (`validate_target`, `is_private_ip`).  
- دوال مساعدة لرفض العمليات غير المصرّح بها خارج المختبر.

## الاستخدام النموذجي

استدعاء من مسارات المختبر أو التحقق قبل تشغيل شيء على هدف؛ التفاصيل الدقيقة للدوال في الملف المصدر.

## التبعيات

`config.SAFETY_POLICY`, `config.PRIVATE_NETWORK_RANGES`
