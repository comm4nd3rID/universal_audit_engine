
# توسعه Adapter، Handler و Parser جدید

## قواعد معماری

- Core نباید ماژول vendor-specific را import کند.
- Adapter فقط عملیات کشف و جمع‌آوری Evidence را انجام می‌دهد.
- Handler فقط Check را به Evidence تبدیل می‌کند.
- Evaluator تصمیم PASS/FAIL/N/A را می‌گیرد و نباید شبکه را بشناسد.
- Registryها مستقل‌اند.
- هیچ Plugin یا Audit File از مسیر دلخواه به‌صورت پویا اجرا نمی‌شود.
- هر قابلیت جدید باید unit، integration و golden test داشته باشد.

## افزودن Handler

1. Canonical Type موجود را reuse کنید یا Type جدید تعریف کنید.
2. کلاس جدید از `BaseHandler` ارث‌بری کند.
3. `supported_check_types` و `can_handle` را صریح تعریف کنید.
4. در `collect` فقط از قرارداد Adapter استفاده کنید.
5. Evidence شامل source، command/query، raw output، timestamp و وضعیت truncation باشد.
6. Handler را در `build_default_handler_registry` ثبت کنید.
7. evaluator و tests مربوطه را اضافه کنید.

نمونه:

```python
from universal_audit.handlers.base import BaseHandler

class ExampleReadOnlyHandler(BaseHandler):
    handler_id = "example.readonly"
    supported_check_types = {"EXAMPLE_READONLY"}

    def collect(self, check, adapter, context):
        result = adapter.execute_readonly(
            check.parameters["cmd"],
            timeout=context.get("command_timeout", 30),
        )
        return self.evidence(
            source="SSH_COMMAND",
            command=check.parameters["cmd"],
            output=result.stdout,
            exit_code=result.exit_code,
            stderr=result.stderr,
            truncated=result.truncated,
        )
```

## افزودن Adapter

Adapter باید:
- `platform_id` ثابت داشته باشد.
- `identify(ip_address)` پیاده کند.
- `execute_readonly` را از Command Policy عبور دهد.
- `read_file` را به مسیرهای مجاز محدود کند.
- `get_config` را فقط در صورت نیاز پیاده کند.
- `close` را پیاده کند.
- Host key verification را دور نزند.

سپس Adapter را در `build_default_adapter_registry` ثبت کنید.

## افزودن Parser Family

Parser باید:
- Header و Metadata را از بدنه جدا کند.
- quoted multiline را حفظ کند.
- nesting را stack-based parse کند.
- raw_text و source_location بدهد.
- unknown fieldها را حفظ کند.
- syntax ناشناخته را بی‌صدا حذف نکند.

Parser مناسب را در `ParserRegistry` ثبت و Normalizer متناظر را اضافه کنید.

## Command Policy

افزودن Handler بدون افزودن Policy مجاز نیست. فرمان باید:
- read-only بودنش برای همان Platform/Version بررسی شده باشد.
- آرگومان‌های آن محدود باشند.
- shell metacharacterها و redirection به‌صورت پیش‌فرض ممنوع باشند.
- روی تجهیز Lab تست شود.
- تست منفی برای فرمان تغییردهنده داشته باشد.

## معیار پذیرش Plugin

- Golden fixture واقعی یا کوچک‌شده
- تست parser و source location
- تست positive/negative/unknown/error
- تست timeout و permission denied
- تست redaction
- تست Command Policy deny-by-default
- تست schema backward compatibility
- ثبت نسخه و compatibility در مستندات
