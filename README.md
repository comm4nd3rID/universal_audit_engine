
# Universal Audit & Compliance Assessment Engine

نسخه `1.0.0` — موتور ارزیابی Read-only برای فایل‌های Tenable-compatible `.audit`

این پروژه بر اساس SDD ارائه‌شده و شش فایل Audit واقعی پیاده‌سازی شده است. معماری Component-Based است: Parser، Normalizer، Registryها، Adapterها، Handlerها، Evaluator، Condition Engine، Review Manager و Reporting/Storage مستقل هستند.

## محدوده پشتیبانی واقعی

| خانواده | فایل‌های موجود | Checkها |
|---|---:|---:|
| Cisco IOS XE 17.x | L1 / L2 | 137 |
| FortiGate 7.4.x | L1 / L2 | 118 |
| VMware ESXi 9.0 Unix | L1 / L2 | 56 |
| **مجموع** | **6 فایل** | **311** |

فایل‌های Chrome، IIS و SQL Server در ورودی این پروژه موجود نبودند؛ بنابراین Adapter یا پشتیبانی اجرایی برای آن‌ها ادعا نمی‌شود.

## قابلیت‌ها

- Parser اختصاصی برای pseudo-XML فایل‌های Audit؛ بدون اجرای محتوای Audit.
- استخراج Metadata، Variables، Checkها، IF/THEN/ELSE، AND/OR و Report Directive.
- نگهداری `raw_definition`، محل منبع و شناسه پایدار برای هر Check.
- Variable resolution با اولویت override اپراتور بر default فایل.
- Adapterهای SSH برای Cisco IOS XE، FortiGate و VMware ESXi.
- Handlerهای مستقل برای `CONFIG_CHECK`، `CONFIG_CHECK_NOT`، `BANNER_CHECK`، `CMD_EXEC` و `FILE_CONTENT_CHECK`.
- Command allowlist مبتنی بر پلتفرم؛ فرمان ناشناخته اجرا نمی‌شود.
- اجرای ترتیبی، timeout، ثبت attempt و ادامه پس از خطای قابل بازیابی.
- Condition Engine با اجرای eager شرط‌ها و ثبت شاخه اجرا‌نشده.
- Manual Review تعاملی، justification اجباری، retry، skip و abort.
- گزارش JSON، schema validation، redaction و checkpoint پس از هر Check.
- ذخیره‌سازی Run یکتا؛ گزارش نهایی قبلی overwrite نمی‌شود.

## پیش‌نیازها

- Python `3.12+`
- دسترسی SSH از ماشین اجراکننده به تجهیز
- کلید میزبان SSH ثبت و از مسیر مستقل تأیید شده باشد
- برای اجرای SSH: `paramiko`
- برای اعتبارسنجی کامل JSON Schema: `jsonschema`

## نصب

### نصب آنلاین

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install .
```

### نصب در شبکه Offline

Wheelهای موردنیاز را از مخزن داخلی یا ماشین متصل دریافت و به ماشین اجرا منتقل کنید. سپس:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install --no-index --find-links ./wheelhouse .
```

حداقل wheelهای لازم:
- `paramiko` و وابستگی‌های آن
- `jsonschema` و وابستگی‌های آن
- `setuptools` و `wheel` برای build در صورت نصب از source

اگر فقط Parse/Validate آفلاین لازم است، بخش Parser با کتابخانه استاندارد Python کار می‌کند؛ برای `run` نصب Paramiko ضروری است.

## اعتبارسنجی فایل‌های Audit بدون اتصال SSH

```bash
uaudit validate --audit audit_profiles/CIS_Cisco_IOS_XE_17.x_v2.2.1_L1.audit
uaudit validate --audit audit_profiles/CIS_FortiGate_7.4.x_v1.0.1_L1.audit
uaudit validate --audit audit_profiles/CIS_VMware_ESXi_9.0_v1.0.0_L1_Unix.audit
```

خروجی Parse شامل خانواده نحوی، پلتفرم، Profile، SHA-256، تعداد Checkها و توزیع Canonical Check Typeهاست.

برای خروجی مدل Canonical به JSON:

```bash
uaudit parse \
  --audit audit_profiles/CIS_Cisco_IOS_XE_17.x_v2.2.1_L1.audit \
  --output cisco-l1-canonical.json
```

## آماده‌سازی SSH امن

1. حساب read-only اختصاصی برای ابزار بسازید.
2. فقط مجوزهای لازم برای مشاهده Configuration/Status و خواندن فایل‌های مشخص را بدهید.
3. اثر واقعی privilege روی نسخه تجهیز را در Lab آزمایش کنید.
4. کلید SSH میزبان را از طریق Console یا منبع مورد اعتماد تجهیز دریافت کنید.
5. Fingerprint را خارج از کانال SSH تأیید کنید؛ سپس کلید را در `known_hosts` ثبت کنید.
6. از `AutoAddPolicy` استفاده نمی‌شود؛ Host key ناشناخته رد خواهد شد.

نمونه دریافت کلید (صرفاً دریافت، نه تأیید هویت):

```bash
ssh-keyscan -H -p 22 192.0.2.10 >> ~/.ssh/known_hosts
ssh-keygen -lf ~/.ssh/known_hosts
```

Fingerprint نمایش‌داده‌شده را با مقدار مورد تأیید ادمین/Console تطبیق دهید. صرف اجرای `ssh-keyscan` به معنی تأیید هویت نیست.

## اجرای Assessment

نمونه Cisco:

```bash
uaudit run \
  --target 192.0.2.10 \
  --audit audit_profiles/CIS_Cisco_IOS_XE_17.x_v2.2.1_L1.audit \
  --username audit-readonly \
  --platform cisco_ios_xe \
  --known-hosts ~/.ssh/known_hosts
```

نمونه FortiGate:

```bash
uaudit run \
  --target 192.0.2.20 \
  --audit audit_profiles/CIS_FortiGate_7.4.x_v1.0.1_L1.audit \
  --username audit-readonly \
  --platform fortigate \
  --known-hosts ~/.ssh/known_hosts
```

نمونه ESXi:

```bash
uaudit run \
  --target 192.0.2.30 \
  --audit audit_profiles/CIS_VMware_ESXi_9.0_v1.0.0_L1_Unix.audit \
  --username audit-readonly \
  --platform vmware_esxi \
  --known-hosts ~/.ssh/known_hosts
```

`--platform auto` نیز موجود است. در حالت Auto، ابزار با فرمان‌های شناسایی Read-only پلتفرم را تشخیص می‌دهد. برای اجرای سازمانی، انتخاب صریح Platform توصیه می‌شود.

در صورت نامشخص بودن نسخه یا ناسازگاری نسخه هدف با Benchmark، اجرا متوقف می‌شود. فقط پس از بررسی دستی می‌توان `--allow-version-mismatch` را اضافه کرد.

### Variable Override

Defaultهای خود Audit به‌صورت خودکار اعمال می‌شوند. برای Override، فایل JSON بسازید:

```json
{
  "DNS_SERVER_1": "192.0.2.53",
  "DNS_SERVER_2": "192.0.2.54",
  "TIMEZONE": "Asia/Tehran"
}
```

مجوز فایل باید محدود باشد:

```bash
chmod 600 variables.json
```

سپس:

```bash
uaudit run --target 192.0.2.20 \
  --audit audit_profiles/CIS_FortiGate_7.4.x_v1.0.1_L1.audit \
  --username audit-readonly \
  --platform fortigate \
  --known-hosts ~/.ssh/known_hosts \
  --variables-file variables.json
```

از قراردادن Password یا Secret در آرگومان command line خودداری کنید. فایل override در گزارش فقط به‌صورت مقدارهای redact‌شده برای متغیرهای حساس ثبت می‌شود. برای ESXi، مسیر فایل به allowlist محدود است: `/etc/passwd`، `/etc/ssh/sshd_config` و `/etc/issue`؛ تغییر `SSH_BANNER_FILE` به مسیر دیگر عمداً Unsupported می‌شود.

## Manual Review

در حالت تعاملی، موارد `MANUAL_REVIEW`، `ERROR`، `UNSUPPORTED` و `UNKNOWN` نمایش داده می‌شوند:

- `p`: PASS — justification اجباری
- `f`: FAIL — justification اجباری
- `n`: N/A — justification اجباری
- `r`: Retry — Attempt قبلی حفظ می‌شود
- `s`: Skip — وضعیت unresolved حفظ می‌شود
- `a`: Abort — نتایج تکمیل‌شده ذخیره می‌شوند

برای اجرای بدون Prompt:

```bash
uaudit run ... --no-review
```

در این حالت وضعیت‌های unresolved در گزارش باقی می‌مانند و به FAIL تبدیل نمی‌شوند.

## خروجی و ساختار ذخیره‌سازی

```text
results/
└── <device-id>/
    └── <software-version>/
        └── <timestamp>_<assessment-id>/
            ├── checkpoint.json
            ├── report.json
            └── execution.log
```

- `checkpoint.json`: پس از هر Check به‌روزرسانی می‌شود.
- `report.json`: گزارش نهایی و schema-validated.
- `execution.log`: خلاصه رویدادهای اجرا؛ بدون Password.
- پوشه‌ها با مجوز محدود ساخته می‌شوند.
- نام Run یکتا است و گزارش نهایی قبلی overwrite نمی‌شود.

## تست‌ها

```bash
pip install -e ".[dev]"
pytest -q
```

Golden tests تعداد Checkها و Canonical Typeهای هر شش فایل را کنترل می‌کنند. تست‌ها بدون اتصال شبکه اجرا می‌شوند.

## محدودیت‌های مهم نسخه 1.0

- این نسخه یک MVP عملیاتی با کنترل‌های امنیتی است، نه محصولی که روی همه مدل‌ها/نسخه‌های سخت‌افزاری Certify شده باشد.
- پیش از Production، هر Adapter باید روی مدل و نسخه واقعی سازمان Acceptance Test شود.
- رفتار بعضی semanticsهای خاص Tenable ممکن است در Auditهای دیگر متفاوت باشد؛ در صورت ابهام، نتیجه Manual/Unsupported/Unknown می‌شود.
- دو فرمان پیچیده ESXi که از `find`، `-exec`، Shell loop و `awk` استفاده می‌کنند عمداً اجرا نمی‌شوند؛ نتیجه آن‌ها `UNSUPPORTED` خواهد بود.
- امضای `#TRUSTED` و `#TRUST-RSA-SHA256` در MVP رمزنگاری‌وار Verify نمی‌شود. SHA-256 فایل برای provenance ثبت می‌شود.
- اجرای موازی، IPv6، چند هدف در یک Run، Web UI، دیتابیس مرکزی و Remediation خارج از دامنه‌اند.
- هیچ فرمان Remediation یا تغییر پیکربندی اجرا نمی‌شود.
- فایل‌های Audit پیوست‌شده تحت شرایط مجوز Tenable خود باقی می‌مانند و این پروژه مجوز آن‌ها را تغییر نمی‌دهد.

## مستندات تکمیلی

- [معماری و گردش داده](docs/ARCHITECTURE.md)
- [ماتریس پشتیبانی](docs/SUPPORT_MATRIX.md)
- [راهنمای عملیات و استقرار](docs/OPERATIONS.md)
- [مدل امنیتی](docs/SECURITY.md)
- [توسعه Plugin و Handler جدید](docs/PLUGIN_DEVELOPMENT.md)
- [SDD ورودی](docs/SDD_reference.md)
