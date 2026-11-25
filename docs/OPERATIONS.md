
# راهنمای استقرار و عملیات

## الگوی استقرار پیشنهادی

یک Linux Runner اختصاصی در Management Network:
- Python 3.12+
- نسخه pin شده برنامه و dependencyها
- دسترسی SSH فقط به IPهای مصوب
- `known_hosts` تحت کنترل Change Management
- خروجی‌ها در Storage رمزنگاری‌شده
- اجرای دستی/تأییدشده در MVP

## حساب‌های دسترسی

### Cisco IOS XE
مجوز لازم برای:
- `show version`
- `show running-config`
- `show snmp user`
- `show crypto key mypubkey rsa`
- `terminal length 0`

دسترسی privilege باید در محیط آزمایش تأیید شود. برای Production، فرمان‌های مجاز را با AAA command authorization محدود کنید.

### FortiGate
مجوز لازم برای:
- `get system status`
- `show full-configuration`

پروفایل مدیریتی read-only با مجوز مشاهده configuration/status توصیه می‌شود. خروجی Full Configuration ممکن است حاوی مقادیر حساس باشد.

### VMware ESXi
مجوز لازم برای:
- فرمان‌های دقیق ESXi که در Command Policy آمده‌اند
- SFTP read-only فقط روی مسیرهای allowlist شده: `/etc/passwd`، `/etc/ssh/sshd_config` و `/etc/issue`

دسترسی SSH/SFTP را فقط برای پنجره Assessment فعال و طبق سیاست سازمان کنترل کنید.

## اجرای قبل از Production

1. نسخه Python و dependencyها را در محیط تست ثابت کنید.
2. هر شش فایل را با `uaudit validate` بررسی کنید.
3. Host key تمام Targetها را از کانال مستقل تأیید کنید.
4. با حساب read-only، اتصال و فرمان‌های شناسایی را تست کنید.
5. روی یک تجهیز Lab از هر خانواده اجرا کنید.
6. Evidence خام و خروجی‌های Report را با خروجی CLI دستی مقایسه کنید.
7. تمام Checkهای Manual/Unsupported/Error را با مالک فنی تجهیز مرور کنید.
8. سپس روی یک Target غیرحساس Pilot اجرا کنید.
9. بعد از تأیید، Runهای سازمانی را با Change/Assessment ID ثبت کنید.

## مدیریت خروجی

هر Run یک directory مستقل دارد. `checkpoint.json` پس از هر Check تکمیل‌شده Atomic به‌روزرسانی می‌شود. `report.json` نهایی با روش عدم overwrite منتشر می‌شود.

پیشنهاد:
- انتقال reportها به مخزن شواهد سازمانی
- نگهداری `execution.log` همراه report
- ثبت SHA-256 فایل Audit در سامانه GRC/Change
- تعریف retention متناسب با سیاست شواهد
- محدودکردن دسترسی به Evidence خام

## بازیابی پس از قطع اجرا

- اگر اتصال SSH یا Authentication در مرحله Preflight شکست بخورد، گزارش مستقل ساخته می‌شود و تمام Checkها به‌صورت `ERROR/BLOCKED` ثبت می‌شوند؛ هیچ‌کدام FAIL نمی‌شوند.
- اگر Platform یا Version تأیید نشود، گزارش Preflight با `UNKNOWN` یا `UNSUPPORTED` ساخته می‌شود و Checkها اجرا نمی‌شوند.
- اگر اپراتور Abort کند، Run با `INTERRUPTED` ثبت می‌شود.
- اگر خطای قابل بازیابی رخ دهد، Check به ERROR می‌رود و اجرای Checkهای مستقل ادامه پیدا می‌کند.
- اگر Process به‌صورت ناگهانی terminate شود، آخرین checkpoint باقی می‌ماند.
- در نسخه 1.0 امکان resume خودکار از checkpoint وجود ندارد؛ Run جدید ایجاد کنید و checkpoint قبلی را به‌عنوان Evidence نگه دارید.

## عیب‌یابی

| نشانه | علت محتمل | اقدام |
|---|---|---|
| Unknown host key | Host key در known_hosts نیست یا تغییر کرده | Fingerprint را از کانال مستقل بررسی و سپس ثبت کنید |
| Authentication failed | حساب/کلید/AAA | credential و مجوز SSH را با ادمین بررسی کنید |
| Platform unidentified | خروجی شناسایی با الگوی Adapter سازگار نیست | Platform صریح انتخاب و نسخه/مدل را دستی بررسی کنید |
| Platform mismatch | Audit و Target از یک خانواده نیستند | Audit صحیح را انتخاب کنید |
| Version not confirmed | نسخه هدف از Benchmark پشتیبانی‌شده خارج یا استخراج نشده | نسخه را دستی بررسی کنید؛ فقط سپس `--allow-version-mismatch` |
| UNSUPPORTED | فرمان در allowlist نیست یا Handler موجود نیست | آن را دستی بررسی کنید؛ برای افزودن پشتیبانی Change و Test لازم است |
| ERROR / COMMAND_TIMEOUT | فرمان طولانی یا ارتباط ناپایدار | Timeout، وضعیت SSH و خروجی command را بررسی کنید |
| UNKNOWN / MISSING_VARIABLE | متغیر ضروری resolve نشده | فایل variables با مجوز 0600 تهیه کنید |
