# `gui/app.py`

## الدور

النافذة الرئيسية **`VulnIntelApp`** — قلب التطبيق: واجهة CustomTkinter، تهيئة قاعدة البيانات، المصادر، المحلل، الذكاء الاصطناعي، و**خط أنابيب المراقبة الدائم** في خيط خلفي.

---

## التهيئة (`__init__`)

| خطوة | ماذا يحدث |
|------|-----------|
| المظهر | `ctk.set_appearance_mode`, `set_default_color_theme` من `config`. |
| النافذة | عنوان، حجم، لون خلفية `COLORS["bg_primary"]`. |
| قاعدة البيانات | إذا تجاوز حجم `DB_PATH` ~50MB يُعاد تسمية الأرشيف؛ ثم `init_database` → `DatabaseManager`. |
| أنظمة | `LabManager`, `CVEAnalyzer`, `AIAnalyzer`. |
| مصادر | قاموس `sources`: `nvd`, `github`, `exploitdb`, `sploitus`. |
| حالة | `_monitoring=True`, خيط pipeline لاحقًا. |
| واجهة | `_build_ui()` ثم `_show_frame("dashboard")`. |
| تشغيل تلقائي | `after(1000, _start_pipeline)` يبدأ الخيط بعد ثانية. |

---

## بناء الواجهة (`_build_ui`)

### الشريط الجانبي (`sidebar`)

- إطار ثابت العرض ~240px، حدود، خلفية `bg_secondary`.  
- **رأس**: أيقونة درع، عنوان VulnIntel، سطر فرعي النسخة.  
- **شريط حالة Pipeline**: إطار بحدود ملونة، نقطة `●` (`monitor_dot`)، نص الحالة (`monitor_label`)، سطر تفصيل (`monitor_detail`).  
- **قائمة تنقل**: أزرار لكل إطار؛ عند النقر يُستدعى `_show_frame(name)`.  
- **أسفل**: زر Force Sync، زر Stop/Start Monitor، `status_label`.  
- **صندوق Safety**: نص "Safety: ENFORCED".

### منطقة المحتوى (`content_area`)

قاموس `self.frames` يضم كل الإطارات مع التبعيات المناسبة (مثل `ai_analyzer` لـ Public Search و Queue).

---

## التبديل بين الإطارات (`_show_frame`)

1. يحدّث ألوان أزرار التنقل (نشط = `bg_tertiary` + `accent_primary`).  
2. يخفي الإطار السابق `pack_forget()`.  
3. يعرض الإطار الجديد `pack(fill="both", expand=True)`.  
4. إن وُجدت `refresh()` على الإطار يُستدعى.

---

## خط الأنابيب (`_start_pipeline` / `_pipeline_loop`)

- يعمل على **`threading.Thread(..., daemon=True)`**.  
- طالما `_monitoring`: يزيد `_sync_cycle` ويعيد المراحل التالية.

### المرحلة 1 — جلب من المصادر

لكل `(src_name, source)` في `sources.items()`:

- `fetch_recent(days_back=7, limit=40)`.  
- إن وُجدت نتائج: `analyzer.store_source_results`.  
- إن كان المصدر exploitdb أو sploitus: لكل عنصر فيه `exploit_url` → `db.add_exploit`.

### المرحلة 2 — توليد Detections

لكل CVE في DB: إن نقص sigma أو yara أو ioc يُولَّد ويُكتب تحت `data/detections/` ويُسجَّل في `detections`.

### المرحلة 3 — بحث exploits + AI

لكل CVE بدون `has_public_exploit`:

- بناء `search_queries` + استعلامات من `ai_analyzer.generate_exploit_search_queries`.  
- بحث متوازي في exploitdb و sploitus؛ ثم بحث GitHub `_search_github_exploits`.  
- اختيار مرشح + تنزيل أفضل artifact من GitHub إن أمكن → `public_exploits/`.  
- إن لم يُوجد شيء: `analyze_failed_exploit_search` → مجلد `data/ai_exploits/<CVE>/`.  
- تأخير `sleep(10)` بين محاولات AI الثقيلة.

### نهاية الدورة

تحديث شريط المراقبة، `_refresh_current_frame`, انتظار `DEFAULT_SYNC_INTERVAL` ثانية قبل الدورة التالية.

---

## دوال مساعدة

| دالة | غرض |
|------|-----|
| `_search_github_exploits` | GitHub repository search لاستعلام CVE/منتج. |
| `_download_best_github_artifact` | تنزيل blob raw أو README كـ fallback. |
| `_toggle_monitor` | إيقاف/تشغيل الخيط. |
| `_manual_sync` | مزامنة يدوية في خيط منفصل. |
| `_update_monitor`, `_set_detail`, `_set_status`, `_log_to_ui` | تحديث UI عبر `after()` حيث يلزم. |
| `_refresh_current_frame` | استدعاء `refresh` على الإطار الحالي. |
| `destroy` | إيقاف المراقبة وإغلاق الاتصال بـ SQLite. |

---

## التبعيات الرئيسية

`config`, `database.*`, `lab.lab_manager`, `analysis.*`, `sources.*`, جميع ملفات `gui/*_frame.py`.

---

## ملخص الشكل البصري للنافذة

```
┌───────────────┬──────────────────────────────────────────────┐
│ Sidebar       │  Content (إطار واحد ملء المنطقة)               │
│ Logo + Status │                                              │
│ Nav buttons   │                                              │
│ Sync / Stop   │                                              │
│ Safety box    │                                              │
└───────────────┴──────────────────────────────────────────────┘
```

السمة **داكنة**؛ الألوان من `COLORS`؛ الخطوط غالبًا Segoe UI للعناوين وConsolas لمعرفات CVE في بعض المواضع.
