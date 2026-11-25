
# مدل امنیتی و کنترل‌های دفاعی

## اصول

1. Audit File داده غیرقابل‌اعتماد است، نه کد اجرایی.
2. فقط عملیات Read-only مجاز است.
3. Command Policy به‌صورت deny-by-default عمل می‌کند.
4. SSH Host Key باید از قبل مورد اعتماد باشد.
5. Password در command line، log و report ثبت نمی‌شود.
6. Evidence و گزارش‌ها ممکن است حاوی اطلاعات حساس باشند و باید محدود نگهداری شوند.

## SSH

- `paramiko` استفاده می‌شود.
- `RejectPolicy` فعال است؛ Host key ناشناخته پذیرفته نمی‌شود.
- `load_system_host_keys` و فایل `--known-hosts` پشتیبانی می‌شود.
- هیچ `AutoAddPolicy` یا Trust-on-first-use خودکار وجود ندارد.
- برای Production، از SSH key یا حساب service با دسترسی حداقلی استفاده شود.

## Command Policy

فرمان‌های Cisco و FortiGate باید دقیقاً در allowlist باشند. برای ESXi فقط فرمان‌های مشخص Audit که به‌عنوان read-only بررسی شده‌اند مجازند. Pipelineهای ساده `grep` به اجرای محلی فیلتر تبدیل می‌شوند. Pipelineهای shell پیچیده Unsupported می‌مانند.

هرگونه `set`, `configure`, `write`, `save`, `reload`, `reboot`, `delete`, `remove` یا remediation در allowlist نیست.

## File Read

در ESXi فقط این مسیرهای دقیق قابل خواندن هستند:
- `/etc/passwd`
- `/etc/ssh/sshd_config`
- `/etc/issue`

مسیر absolute، بدون `..` و بدون NUL باید باشد. مسیر دلخواه زیر `/etc` یا `/var/db` مجاز نیست. SFTP فقط برای خواندن استفاده می‌شود.

## Regex

- طول Regex و طول Evidence محدود است.
- الگوهای دارای nested quantifier مشکوک توسط Guard رد می‌شوند.
- Regex نامعتبر/ردشده به ERROR تبدیل می‌شود، نه FAIL.
- برای Regexهای Audit جدید، تست ReDoS و Golden Test اضافه شود.

## Redaction

خروجی‌هایی که شامل password، passwd، secret، community، psksecret، token یا private-key باشند قبل از ذخیره گزارش Redact می‌شوند. مقادیر Variableهای حساس نیز از خروجی گزارش حذف می‌شوند.

با وجود Redaction، فرض کنید خروجی خام تجهیزات داده حساس دارد. مسیر `results/` را فقط در اختیار تیم مجاز قرار دهید و از انتقال امن/رمزنگاری دیسک استفاده کنید.

## Trust Header

`#TRUSTED` و `#TRUST-RSA-SHA256` در Parser به‌عنوان Header نگهداری/نادیده گرفته می‌شوند و هیچ‌گاه اجرا نمی‌شوند. در نسخه 1.0 امضای دیجیتال verify نمی‌شود. Hash SHA-256 برای تشخیص تغییر فایل در گزارش ثبت می‌شود. منبع Audit باید از قبل مورد اعتماد باشد.

## Production Hardening Checklist

- [ ] حساب read-only مجزا برای هر Platform
- [ ] SSH Host Key fingerprint از کانال مستقل تأیید شده
- [ ] ACL شبکه فقط از Runner به Targetهای مصوب
- [ ] مسیر خروجی با مجوز `0700` و فایل با `0600`
- [ ] رمزنگاری Volume/Backup خروجی‌ها
- [ ] زمان‌بندی و پنجره اجرای مصوب
- [ ] نسخه Audit و SHA-256 ثبت‌شده در Change/Assessment record
- [ ] Acceptance Test روی مدل و نسخه واقعی تجهیز
- [ ] بازبینی دستی Checkهای Unsupported/Manual
- [ ] کنترل دسترسی و retention برای report/checkpoint/log
