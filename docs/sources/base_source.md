# `sources/base_source.py`

## الدور

تعريف الواجهة المجردة **`VulnSource`** التي يجب أن تحققها كل المصادر.

## العضويات المطلوبة

| عضو | الوصف |
|-----|---------|
| `source_name` | اسم المصدر (property). |
| `fetch_recent(days_back, limit)` | جلب CVEs حديثة كنماذج موحّدة. |
| `search(query, limit)` | بحث نصي أو CVE ID. |

قد تتضمن دوال مساعدة مشتركة في نهاية الملف.

## التطبيقات

`NVDSource`, `GitHubAdvisoriesSource`, `ExploitDBSource`, `SploitusSource`.
