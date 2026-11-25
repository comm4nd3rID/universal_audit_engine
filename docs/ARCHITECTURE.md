
# معماری فنی

## جریان کلی

```text
CLI / Input Validator
        |
        v
Audit Parser Registry
        |
        v
Header + Metadata + Lexer + Recursive Parser
        |
        v
Audit AST -> Normalizer -> Canonical Audit Model
        |                               |
        |                               v
        |                       Variable Resolver
        |                               |
        v                               v
Target Discovery -> Adapter Registry -> Platform Adapter / SSH Transport
                                            |
                                            v
Check Dispatcher -> Handler Registry -> Check Handler -> Evidence
                                            |
                                            v
                                  Compliance Evaluator
                                            |
                         +------------------+------------------+
                         |                                     |
                  Condition Engine                      Review Manager
                         |                                     |
                         +------------------+------------------+
                                            |
                                     Check Results
                                            |
                               Result/Report Normalization
                                            |
                               JSON Schema Validation
                                            |
                                   Atomic Storage
```

## لایه‌ها و مسئولیت‌ها

### CLI و Input Validation
- دریافت Target IPv4، مسیر Audit، Platform، Username، متغیرهای Override و مسیر خروجی.
- اعتبارسنجی فایل، IP و مجوز فایل متغیرها.
- Password از `getpass` گرفته می‌شود؛ در آرگومان shell دریافت نمی‌شود.

### Audit Parser
- `Header/Metadata`: استخراج Metadata و Variables از ui_metadata کامنت‌شده.
- `Lexer`: تشخیص تگ ساختاری، فیلد key:value، comment و raw line.
- `Recursive Parser`: حفظ nesting و ترتیب تگ‌ها.
- `AST`: نگهداری raw_text و source_location.
- Parser هیچ shell، Python یا expression داخل فایل Audit را اجرا نمی‌کند.

### Normalizer
- نگاشت Cisco، FortiGate و Unix/ESXi به Platform ID استاندارد.
- نگاشت Check Type به Canonical Type.
- تولید Check ID پایدار از hash فایل، مسیر node و محتوای تعریف.
- نگهداری تمام فیلدهای اصلی در `raw_fields` و `raw_definition`.
- نگاشت FortiGate بدون type صریح تنها وقتی انجام می‌شود که الگوی context/regex/expect شناخته‌شده باشد.

### Registries
سه Registry مستقل وجود دارد:
- Parser Registry: انتخاب Parser برای خانواده نحو.
- Adapter Registry: انتخاب Adapter برای پلتفرم.
- Handler Registry: انتخاب Handler براساس Canonical Check Type و پلتفرم.

### Adapters
قرارداد Adapter عملیات `identify`، `execute_readonly`، `read_file`، `get_config` و `close` را ارائه می‌کند. Adapter مسئول تشخیص و جمع‌آوری داده است؛ منطق PASS/FAIL در آن قرار ندارد. Cisco و FortiGate از interactive CLI channel استفاده می‌کنند؛ ESXi از SSH exec channel استفاده می‌کند تا stdout، stderr و exit code جدا ثبت شوند.

### Handlers
- Cisco Config: دریافت Running Configuration یا اجرای فرمان Show مشخص‌شده در allowlist.
- Cisco Banner: دریافت Running Configuration.
- FortiGate Context/Regex: دریافت Full Configuration و استخراج stanza مربوط.
- FortiGate Banner: استخراج context و بررسی محتوای Banner.
- FortiGate Command: اجرای فرمان read-only مجاز.
- Unix Command: اجرای CMD_EXEC پس از Command Policy.
- Unix File Content/Banner: خواندن فایل با SFTP و کنترل مسیر.

### Evaluator
Evaluator کاملاً Pure است؛ شبکه یا SSH را نمی‌شناسد. فقط Evidence و Check Definition را دریافت می‌کند و Evaluation می‌دهد.

### Condition Engine
- تمام Checkهای داخل شرط به‌صورت eager اجرا می‌شوند.
- AND/OR براساس PASS/FAIL/Unknown محاسبه می‌شود.
- اگر شرط unresolved باشد، شاخه‌ها BLOCKED می‌شوند.
- `auto="WARNING"` و `auto="FAILED"` به‌عنوان metadata ثبت می‌شوند و در MVP semantics اجرایی مستقل ندارند.
- Report Directive به‌تنهایی PASS تولید نمی‌کند.

### Review Manager
برای Manual Review، Error، Unknown و Unsupported امکان PASS/FAIL/N/A با justification، Retry، Skip و Abort فراهم می‌شود.

### Reporting و Storage
- تمام Checkها در گزارش می‌مانند؛ از جمله شاخه اجرا‌نشده.
- JSON Schema بررسی می‌شود.
- Evidence و خروجی‌های حساس Redact می‌شوند.
- Checkpoint و Final Report به‌شکل Atomic نوشته می‌شوند.

## مدل وضعیت

`status` نتیجه انطباق است و `execution_status` چرخه اجرا را بیان می‌کند. برای نمونه:
- Timeout: `ERROR / FAILED`
- Check ناشناخته: `UNSUPPORTED / BLOCKED`
- شاخه اجرا‌نشده: `SKIPPED / BLOCKED`
- تصمیم اپراتور: `PASS|FAIL|N/A / MANUAL`
- انطباق قطعی: `PASS|FAIL / COMPLETED`

Timeout، Authentication Failure، Permission Denied یا Parse Failure هرگز به‌صورت خودکار FAIL نمی‌شوند.
