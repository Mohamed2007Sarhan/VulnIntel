# VulnIntel — فهرس التوثيق (`docs/`)

هذا المجلد يشرح **كل ملفات المصدر** في المشروع، **والترابط بينها**، **ومسار البيانات**، **وواجهة المستخدم (الشكل والخطوات)**.

---

## أين أبدأ؟

| الملف | المحتوى |
|--------|---------|
| [**00-architecture-data-flow.md**](00-architecture-data-flow.md) | المعمارية العامة، مخططات Mermaid، مسار البيانات خطوة بخطوة، شكل الواجهة والتنقل |
| [**data-directories.md**](data-directories.md) | مجلدات `data/` المُنتَجة (قواعد، detections، exploits، ai_exploits) |
| [**config.md**](config.md) | الإعدادات العامة، المسارات، Groq، حدود المعدل |
| [**main.md**](main.md) | نقطة تشغيل البرنامج |

---

## هيكل الملفات (مرآة للكود)

### الجذر (`no/`)

| الملف في المستودع | ملف الشرح |
|-------------------|-----------|
| `main.py` | [main.md](main.md) |
| `config.py` | [config.md](config.md) |
| `sploitus_fetch.py` | [sploitus_fetch.md](sploitus_fetch.md) |

### `analysis/`

| الملف | الشرح |
|-------|--------|
| `__init__.py` | [analysis/__init__.md](analysis/__init__.md) |
| `ai_analyzer.py` | [analysis/ai_analyzer.md](analysis/ai_analyzer.md) |
| `cve_analyzer.py` | [analysis/cve_analyzer.md](analysis/cve_analyzer.md) |
| `exploit_classifier.py` | [analysis/exploit_classifier.md](analysis/exploit_classifier.md) |
| `safety_policy.py` | [analysis/safety_policy.md](analysis/safety_policy.md) |

### `database/`

| الملف | الشرح |
|-------|--------|
| `__init__.py` | [database/__init__.md](database/__init__.md) |
| `models.py` | [database/models.md](database/models.md) |
| `db_manager.py` | [database/db_manager.md](database/db_manager.md) |

### `generators/`

| الملف | الشرح |
|-------|--------|
| `__init__.py` | [generators/__init__.md](generators/__init__.md) |
| `sigma_generator.py` | [generators/sigma_generator.md](generators/sigma_generator.md) |
| `yara_generator.py` | [generators/yara_generator.md](generators/yara_generator.md) |
| `ioc_generator.py` | [generators/ioc_generator.md](generators/ioc_generator.md) |
| `report_generator.py` | [generators/report_generator.md](generators/report_generator.md) |
| `remediation.py` | [generators/remediation.md](generators/remediation.md) |

### `sources/`

| الملف | الشرح |
|-------|--------|
| `__init__.py` | [sources/__init__.md](sources/__init__.md) |
| `base_source.py` | [sources/base_source.md](sources/base_source.md) |
| `nvd_source.py` | [sources/nvd_source.md](sources/nvd_source.md) |
| `github_advisories.py` | [sources/github_advisories.md](sources/github_advisories.md) |
| `exploitdb_source.py` | [sources/exploitdb_source.md](sources/exploitdb_source.md) |
| `sploitus_source.py` | [sources/sploitus_source.md](sources/sploitus_source.md) |

### `lab/`

| الملف | الشرح |
|-------|--------|
| `__init__.py` | [lab/__init__.md](lab/__init__.md) |
| `lab_manager.py` | [lab/lab_manager.md](lab/lab_manager.md) |
| `sandbox_workflow.py` | [lab/sandbox_workflow.md](lab/sandbox_workflow.md) |

### `gui/`

| الملف | الشرح |
|-------|--------|
| `__init__.py` | [gui/__init__.md](gui/__init__.md) |
| `app.py` | [gui/app.md](gui/app.md) |
| `dashboard_frame.py` | [gui/dashboard_frame.md](gui/dashboard_frame.md) |
| `cve_browser_frame.py` | [gui/cve_browser_frame.md](gui/cve_browser_frame.md) |
| `exploit_frame.py` | [gui/exploit_frame.md](gui/exploit_frame.md) |
| `detection_frame.py` | [gui/detection_frame.md](gui/detection_frame.md) |
| `lab_frame.py` | [gui/lab_frame.md](gui/lab_frame.md) |
| `reports_frame.py` | [gui/reports_frame.md](gui/reports_frame.md) |
| `settings_frame.py` | [gui/settings_frame.md](gui/settings_frame.md) |
| `queue_frame.py` | [gui/queue_frame.md](gui/queue_frame.md) |
| `target_analysis_frame.py` | [gui/target_analysis_frame.md](gui/target_analysis_frame.md) |
| `public_search_frame.py` | [gui/public_search_frame.md](gui/public_search_frame.md) |

### `gui/components/`

| الملف | الشرح |
|-------|--------|
| `__init__.py` | [gui/components/__init__.md](gui/components/__init__.md) |
| `cve_card.py` | [gui/components/cve_card.md](gui/components/cve_card.md) |
| `status_indicator.py` | [gui/components/status_indicator.md](gui/components/status_indicator.md) |
| `search_bar.py` | [gui/components/search_bar.md](gui/components/search_bar.md) |
| `severity_badge.py` | [gui/components/severity_badge.md](gui/components/severity_badge.md) |

---

## ملاحظات

- ملفات تحت `data/` (مثل `data/ai_exploits/.../*.py`) هي **مخرجات مُولَّدة** وليست نواة التطبيق؛ لا يوجد لها صفحة هنا.
- السكربت `sploitus_fetch.py` أداة **CLI مستقلة** (اختيارية) وليست جزءًا من الـ GUI مباشرة.

آخر تحديث يتوافق مع هيكل المستودع الحالي (`VulnIntel v2`).
