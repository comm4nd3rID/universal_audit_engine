
# ماتریس پشتیبانی نسخه 1.0

## Parser Golden Coverage

| فایل | Check count | Canonical type distribution |
|---|---:|---|
| Cisco IOS XE 17.x L1 | 111 | 95 `CISCO_CONFIG_CHECK`, 13 `CISCO_CONFIG_CHECK_NOT`, 3 `CISCO_BANNER_CHECK` |
| Cisco IOS XE 17.x L2 | 26 | 26 `CISCO_CONFIG_CHECK` |
| FortiGate 7.4.x L1 | 83 | 81 `FORTIGATE_CONTEXT_REGEX`, 2 `FORTIGATE_BANNER_CHECK` |
| FortiGate 7.4.x L2 | 35 | 34 `FORTIGATE_CONTEXT_REGEX`, 1 `FORTIGATE_COMMAND` |
| VMware ESXi 9.0 L1 Unix | 52 | 37 `UNIX_COMMAND`, 13 `UNIX_FILE_CONTENT`, 2 `UNIX_BANNER` |
| VMware ESXi 9.0 L2 Unix | 4 | 3 `UNIX_COMMAND`, 1 `UNIX_FILE_CONTENT` |
| **Total** | **311** | |

این اعداد توسط Golden Tests در `tests/golden/audit_counts.json` کنترل می‌شوند.

## پشتیبانی اجرایی

| Platform | Canonical Type | روش Evidence | ارزیابی |
|---|---|---|---|
| Cisco IOS XE | `CISCO_CONFIG_CHECK` | `show running-config` یا فرمان Show صریح در allowlist؛ context extraction | regex/item؛ در صورت ابهام Manual |
| Cisco IOS XE | `CISCO_CONFIG_CHECK_NOT` | Running Configuration | وجود الگوی ممنوع = FAIL |
| Cisco IOS XE | `CISCO_BANNER_CHECK` | Running Configuration | بررسی substring محتوای تعریف‌شده |
| FortiGate | `FORTIGATE_CONTEXT_REGEX` | `show full-configuration` و context extraction | `regex`, `expect`, `not_expect` |
| FortiGate | `FORTIGATE_BANNER_CHECK` | Full Configuration و context مشخص | بررسی substring محتوای Banner |
| FortiGate | `FORTIGATE_COMMAND` | فرمان دقیق allowlist | expect یا Manual Review |
| ESXi | `UNIX_COMMAND` | فرمان دقیق read-only allowlist | expect یا Manual Review |
| ESXi | `UNIX_FILE_CONTENT` | SFTP read-only | regex/expect |
| ESXi | `UNIX_BANNER` | SFTP read-only | substring محتوا |

## فرمان‌های ESXi

فرمان‌های `esxcli ... get/list` و چند فرمان مشخص Status مجازند. Pipelineهای محدود Audit که فقط `grep` دارند، به فرمان پایه Read-only و فیلتر محلی تبدیل می‌شوند. Shell pipeline روی تجهیز اجرا نمی‌شود.

دو فرمان شامل `find`, `-exec`, shell loop و `awk` عمداً Unsupported هستند. این تصمیم برای جلوگیری از اجرای Shell پیچیده از محتوای Audit گرفته شده است.

## خارج از پشتیبانی اجرایی

- Chrome، IIS و SQL Server؛ فایل Audit متناظر ارائه نشده است.
- IPv6، چند Target در یک Run، اجرای موازی، Remediation و Web UI.
- همه Check Typeهای عمومی Tenable.
- اعتبارسنجی رمزنگاری سربرگ TRUST.
- semantics ناشناخته در Auditهای غیر از شش فایل golden.

## قواعد نتیجه

- عدم تطبیق قطعی Evidence با Expected => FAIL.
- Timeout/Permission/Auth/SSH/Regex error => ERROR یا UNKNOWN.
- Handler یا فرمان مجاز وجود ندارد => UNSUPPORTED.
- Audit صریحاً `Manual Review Required` می‌گوید => MANUAL_REVIEW.
- Evidence ناقص یا truncated و عدم مشاهده pattern => UNKNOWN.
- شاخه شرطی اجرا‌نشده => SKIPPED/BLOCKED.
