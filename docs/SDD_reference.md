**سند طراحی نرم‌افزار**\
**Software Design Document (SDD)**

**Universal Audit & Compliance Assessment Engine**



نسخه سند: 1.0

وضعیت: طراحی نسخه اولیه (MVP)

زبان پیاده‌سازی: Python 3.12+

مبنای طراحی: SRS نسخه 1.0 و شش فایل Audit پیوست‌شده

تاریخ: 2026-11-25



نسخه 1.0  |  2026-11-25

Universal Audit & Compliance Assessment Engine | Software Design Document

**کنترل سند و مبنای طراحی**

این سند، طراحی فنی نسخه اولیه را از روی SRS ارائه‌شده و فایل‌های واقعی زیر استخراج می‌کند. هدف، ساخت یک هسته مشترک و افزونه‌پذیر است؛ نه ساخت یک اسکریپت اختصاصی برای هر محصول یا هر نسخه.

| **منبع**                | **مشاهده مستقیم در فایل**                                                                 | **نکته طراحی**                                                                                        |
| ----------------------- | ----------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| Cisco IOS XE 17.x L1    | 111 بلوک \<item>؛ شامل 95 CONFIG_CHECK، 13 CONFIG_CHECK_NOT و 3 BANNER_CHECK              | ساختار \<item> با فیلدهای type، item، context، regex و گاهی content/cmd                               |
| Cisco IOS XE 17.x L2    | 26 بلوک \<item>؛ همگی CONFIG_CHECK                                                        | پروفایل L2 همان خانواده ساختاری Cisco است                                                             |
| FortiGate 7.4.x L1      | 83 بلوک \<custom_item>؛ دو مورد BANNER_CHECK و بسیاری از موارد دارای context/regex/expect | بخش عمده custom_itemها type صریح ندارند؛ از check_type و فیلدهایشان برای تشخیص handler استفاده می‌شود |
| FortiGate 7.4.x L2      | 35 بلوک \<custom_item>؛ عمدتاً context/regex/expect                                       | در این فایل نیز بسیاری از custom_itemها بدون type صریح هستند                                          |
| VMware ESXi 9.0 L1 Unix | 52 بلوک \<custom_item>؛ 37 CMD_EXEC، 13 FILE_CONTENT_CHECK و 2 BANNER_CHECK               | ساختار شرطی IF/condition/THEN/ELSE و report نیز وجود دارد                                             |
| VMware ESXi 9.0 L2 Unix | 4 بلوک \<custom_item>؛ 3 CMD_EXEC و 1 FILE_CONTENT_CHECK                                  | نمونه کوچک‌تر از همان خانواده Unix است                                                                |



محدوده واقعی MVP بر اساس فایل‌های موجود: Cisco IOS XE، FortiGate و VMware ESXi. در SRS نام Chrome، IIS و SQL Server نیز آمده است، اما فایل Audit متناظر آن‌ها در مجموعه پیوست‌شده وجود ندارد؛ بنابراین پشتیبانی عملی آن‌ها در این نسخه ادعا نمی‌شود و فقط مسیر توسعه برایشان تعریف می‌شود.

نکته مهم: فایل‌های Audit شامل سربرگ‌های #TRUSTED و #TRUST-RSA-SHA256 هستند. این سربرگ‌ها امضای/اعتماد فایل‌اند و نباید به‌عنوان دستورات اجرایی یا بخشی از بدنه Audit تفسیر شوند. اعتبارسنجی رمزنگاری امضا در MVP خارج از دامنه است؛ فایل باید از منبع مورد اعتماد دریافت شود.

**1. هدف و اصول طراحی**

هدف، تبدیل Audit File به مدل میانی استاندارد، جمع‌آوری شواهد از تجهیز، ارزیابی کنترل‌ها و تولید گزارش JSON است. برای اضافه‌کردن پلتفرم یا نوع Check جدید، توسعه‌دهنده باید بتواند یک Adapter یا Handler جدید ثبت کند، بدون آنکه Core Engine تغییر کند.

Core کوچک و مستقل از Vendor: منطق گردش کار، وضعیت‌ها، ارزیابی و گزارش‌سازی در هسته قرار می‌گیرد.

Parser و Normalizer مستقل: نحو Tenable-compatible فقط در لایه Parser شناخته می‌شود؛ سایر اجزا با مدل داخلی کار می‌کنند.

Adapter مسئول ارتباط و کشف هدف است؛ Handler مسئول جمع‌آوری Evidence برای یک نوع Check است.

Evaluator مسئول تفسیر Evidence است و نباید فرمانی اجرا کند.

خطای اجرا با FAIL یکی نیست؛ نبود شواهد یا نبود قابلیت باید به ERROR، UNKNOWN یا UNSUPPORTED منجر شود.

اجرای نسخه اول ترتیبی و Read-only است؛ هیچ Remediation اجرا نمی‌شود.

رفتار ناشناخته به‌صورت امن متوقف می‌شود؛ Check ناشناخته هرگز بی‌صدا حذف یا اجرا نمی‌شود.

**2. دامنه نسخه اولیه**

**2.1 قابلیت‌های داخل دامنه**

CLI برای دریافت IPv4، مسیر فایل .audit و اطلاعات اتصال موردنیاز.

خواندن Metadata، Variables، Checkها و ساختارهای شرطی نمونه‌های Cisco، FortiGate و ESXi.

مدل میانی مشترک برای Check، شرط، Variable، شواهد و نتیجه.

اتصال SSH برای Cisco IOS XE، FortiGate و ESXi؛ در ESXi اجرای فرمان/خواندن فایل از راه دور.

پشتیبانی اولیه از CONFIG_CHECK، CONFIG_CHECK_NOT، BANNER_CHECK، CMD_EXEC، FILE_CONTENT_CHECK و Checkهای FortiGate مبتنی بر context/regex/expect.

اجرای ترتیبی، timeout، retry و ثبت تاریخچه تلاش‌ها.

بازبینی تعاملی در ترمینال برای Checkهای Manual Review، Unsupported، Error و Unknown.

گزارش JSON با تمام Checkها، شامل موارد اجرا‌نشده و شاخه‌های شرطی.

ذخیره‌سازی در ساختار device/version/run مطابق SRS.

**2.2 خارج از دامنه MVP**

پشتیبانی واقعی از Chrome، IIS و SQL Server تا زمان ارائه و تحلیل فایل‌های Audit مربوطه.

IPv6، چند هدف در یک Run، اجرای موازی، Web UI، پایگاه داده مرکزی و زمان‌بندی.

Remediation یا هر عملیات تغییردهنده پیکربندی.

پشتیبانی کامل از تمام Check Typeهای Tenable؛ فقط زیرمجموعه‌ای که در فایل‌های پیوست‌شده مشاهده شده یا صریحاً در این سند تعریف شده است.

اعتبارسنجی رمزنگاری امضای #TRUSTED در برابر کلید عمومی ناشر.

**3. معماری کلان**

CLI\
&#x20;|\
&#x20;v\
Assessment Orchestrator\
&#x20;\|-- Input Validator\
&#x20;\|-- Audit Parser --> Audit AST --> Audit Normalizer --> Canonical Audit Model\
&#x20;\|-- Target Discovery --> Adapter Registry --> Platform Adapter --> Connection\
&#x20;\|-- Check Dispatcher --> Handler Registry --> Check Handler --> Evidence\
&#x20;\|-- Condition Engine\
&#x20;\|-- Compliance Evaluator\
&#x20;\|-- Interactive Review Manager\
&#x20;\|-- Result Normalizer\
&#x20;\|-- JSON Schema Validator --> Report Generator --> Result Storage

جهت وابستگی‌ها باید به سمت abstractionهای Core باشد. Adapterها و Handlerها می‌توانند از قراردادهای Core استفاده کنند، اما Core نباید ماژول‌های vendor-specific را import کند.

| **جزء**             | **مسئولیت**                                               | **نباید انجام دهد**                |
| ------------------- | --------------------------------------------------------- | ---------------------------------- |
| CLI / Input Manager | دریافت ورودی، اعتبارسنجی اولیه و نمایش پیام‌ها            | اجرای فرمان یا تحلیل Regex اختصاصی |
| Audit Parser        | Tokenize/parse کردن نحو فایل و تولید AST                  | اتصال به هدف یا تصمیم PASS/FAIL    |
| Audit Normalizer    | تبدیل AST به مدل Canonical و نگهداری raw definition       | اجرای Check                        |
| Target Discovery    | شناسایی Vendor/Platform/Version از طریق Adapterهای کاندید | حدس قطعی بر اساس نام فایل Audit    |
| Adapter             | اتصال، اجرای عملیات خواندن و ارائه قابلیت‌های پلتفرم      | تفسیر سیاست انطباق                 |
| Handler             | تبدیل Check به عملیات جمع‌آوری Evidence                   | تولید گزارش نهایی یا مدیریت CLI    |
| Evaluator           | مقایسه Evidence با Expected/Regex و تعیین نتیجه           | اتصال شبکه یا اجرای فرمان          |
| Review Manager      | گرفتن تصمیم اپراتور و ثبت دلیل                            | تغییر یا حذف Evidence خام          |
| Report/Storage      | تولید JSON معتبر و ذخیره غیرقابل‌overwrite                | تغییر نتیجه‌های محاسبه‌شده         |



**4. طراحی مدل داده Canonical**

تمام فرمت‌های ورودی باید به مدل مشترک زیر تبدیل شوند. این مدل عمداً اطلاعات خام را نیز نگه می‌دارد تا در صورت پشتیبانی‌نشدن یک فیلد، داده از دست نرود.

**4.1 موجودیت‌های اصلی**

| **مدل**            | **فیلدهای کلیدی**                                                                                                         | **توضیح**                                                     |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| AuditDocument      | source_path, file_hash, syntax_family, check_type, metadata, variables, nodes, raw_header                                 | نماینده یک فایل کامل                                          |
| AuditMetadata      | display_name, benchmark_type, benchmark_name, benchmark_version, profile, link, labels                                    | از ui_metadata و سربرگ استخراج می‌شود                         |
| VariableDefinition | name, default, description, value_type, info                                                                              | مقدار پیش‌فرض؛ override باید در زمان اجرا جداگانه نگهداری شود |
| CheckDefinition    | check_id, description, check_type, platform, parameters, expected, context, severity, references, remediation, raw_fields | هر Check قابل گزارش                                           |
| ConditionNode      | operator, auto_policy, children, then_branch, else_branch                                                                 | حفظ ترتیب و روابط شرطی                                        |
| Evidence           | source, command_or_query, raw_output, normalized_value, collected_at, redactions                                          | شواهد خام و امن                                               |
| CheckResult        | status, execution_status, result_source, expected, actual, evidence, error, attempts, operator_decision                   | نتیجه استاندارد                                               |
| AssessmentRun      | assessment_id, target, audit, started_at, ended_at, overall_status, results                                               | اجرای کامل یک Audit روی یک هدف                                |



**4.2 تفکیک وضعیت انطباق از وضعیت اجرا**

| **فیلد**         | **مقادیر**                                                                            | **معنا**                                                              |
| ---------------- | ------------------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| status           | PASS / FAIL / N/A / PENDING / MANUAL_REVIEW / ERROR / UNSUPPORTED / UNKNOWN / SKIPPED | وضعیت قابل مشاهده در خروجی؛ فقط PASS/FAIL/N/A نتیجه قطعی انطباق هستند |
| execution_status | NOT_STARTED / RUNNING / COMPLETED / FAILED / MANUAL / SKIPPED / BLOCKED               | چرخه اجرای Check                                                      |
| result_source    | AUTOMATIC / MANUAL / NONE                                                             | منبع تصمیم نهایی                                                      |
| overall_status   | COMPLETED / COMPLETED_WITH_UNRESOLVED / INTERRUPTED / FAILED                          | وضعیت کل Assessment                                                   |



قاعده کلیدی: timeout، authentication failure، permission denied، command failure و parse failure هرگز به‌صورت خودکار FAIL نمی‌شوند. اگر داده قابل ارزیابی نیست، نتیجه ERROR یا UNKNOWN خواهد بود.

**4.3 شناسه Check**

اگر Audit ID صریحی ارائه نکند، شناسه داخلی پایدار از ترتیب/محتوا ساخته شود؛ برای مثال hash کوتاه از file_hash + node_path + description. شماره ترتیبی صرفاً برای نمایش است و نباید تنها کلید ذخیره‌سازی باشد.

**5. طراحی Parser و پشتیبانی از نحو Audit**

فایل‌های نمونه XML خالص نیستند. بدنه از تگ‌های شبه-XML مانند \<check_type:"Unix">، بلوک‌های \<custom_item> یا \<item> و فیلدهای key:value تشکیل شده است؛ مقادیر نیز ممکن است چندخطی باشند. بنابراین استفاده مستقیم از XML parser برای کل فایل صحیح نیست.

**5.1 Pipeline پارس**

Header Scanner: خطوط ابتدایی، commentها، #TRUSTED و #TRUST-RSA-SHA256 را جدا می‌کند.

Metadata Extractor: محتوای comment شده ui_metadata/spec/variables را استخراج می‌کند.

Lexer: تگ‌های ساختاری، شناسه فیلد، colon، quoted string، escape و متن چندخطی را token می‌کند.

Recursive Parser: بلوک‌های item/custom_item، if/condition/then/else و report را به AST تو‌در‌تو تبدیل می‌کند.

Normalizer: AST را به Canonical Audit Model تبدیل می‌کند و فیلدهای ناشناخته را در raw_fields نگه می‌دارد.

Validation: خطاهای syntax، بلوک‌های ناقص، فیلدهای الزامی و nesting نامعتبر را گزارش می‌کند.

**5.2 قواعد Parser**

Parser باید tolerant در برابر comment و whitespace باشد، اما syntax ناقص را با warning/error مشخص کند.

رشته‌های quoted باید escapeهای "، \\\ و newline را درست حفظ کنند.

فیلدهای multiline مانند info و solution باید تا فیلد بعدی یا پایان بلوک جمع‌آوری شوند.

تگ‌های ساختاری باید stack-based و nesting-aware پردازش شوند؛ Regex ساده برای استخراج بلوک‌های تو‌در‌تو کافی نیست.

metadata کامنت‌شده باید بدون اجرای محتوای آن استخراج شود.

هر node باید source_location (line/column) و raw_text داشته باشد تا خطا و گزارش قابل ردیابی باشد.

Unknown tag/field حفظ شود؛ unknown executable node به UNSUPPORTED تبدیل شود.

**5.3 خانواده‌های نحوی مشاهده‌شده**

| **خانواده** | **نحو/فیلدهای مشاهده‌شده**                                                                                               | **تبدیل Canonical**                                       |
| ----------- | ------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------- |
| Cisco       | \<check_type:"Cisco">، \<item>، type=CONFIG_CHECK/CONFIG_CHECK_NOT/BANNER_CHECK، item، context، regex، content، cmd      | CiscoConfigCheck / CiscoBannerCheck                       |
| FortiGate   | \<check_type:"FortiGate">، \<custom_item>، context، regex، expect، not_expect؛ در بعضی موارد type=BANNER_CHECK           | FortiGateContextRegexCheck؛ برای Banner handler مجزا      |
| Unix / ESXi | \<check_type:"Unix">، \<custom_item>، CMD_EXEC، FILE_CONTENT_CHECK، BANNER_CHECK، cmd، file، expect، regex، is_substring | UnixCommandCheck / UnixFileContentCheck / UnixBannerCheck |
| Conditional | \<if>، \<condition type:"AND\|OR" auto:"...">، \<then>، \<else>، \<report type:"...">                                    | ConditionNode و ReportDirective                           |



**5.4 Variable Resolution**

متغیرهایی مانند @VARIABLE_NAME@ و مقادیر پیش‌فرض تعریف‌شده در ui_metadata باید قبل از اجرای Check resolve شوند. اولویت پیشنهادی: override اپراتور > default فایل > مقدار خالی/تعریف‌نشده. مقدار resolve‌شده در گزارش ثبت شود، اما secret variableها باید redact شوند. اگر متغیر ضروری resolve نشود، Check به UNKNOWN یا ERROR با دلیل MISSING_VARIABLE می‌رود.

**6. Registry و افزونه‌پذیری**

**6.1 سه Registry مستقل**

| **Registry**     | **کلید انتخاب**                                  | **خروجی**                            |
| ---------------- | ------------------------------------------------ | ------------------------------------ |
| Parser Registry  | syntax_family / check_type family                | Parser مناسب برای Audit              |
| Adapter Registry | platform_id + capabilities + version constraints | Adapter مناسب برای هدف               |
| Handler Registry | normalized_check_type + platform capabilities    | Handler مناسب برای جمع‌آوری Evidence |



برای مثال، افزودن یک Check Type جدید نباید مستلزم تغییر CheckDispatcher باشد. توسعه‌دهنده فقط کلاس Handler را پیاده‌سازی و با decorator/entry point ثبت می‌کند. اگر هیچ Handler سازگاری پیدا نشود، نتیجه UNSUPPORTED با raw definition کامل خواهد بود.

**6.2 قرارداد Adapter**

class PlatformAdapter(Protocol):\
&#x20;   platform_id: str\
&#x20;   capabilities: set[str]\
\
&#x20;   def identify(self, target, credentials) -> DeviceInfo: ...\
&#x20;   def connect(self, target, credentials) -> None: ...\
&#x20;   def execute_readonly(self, operation, timeout) -> CommandResult: ...\
&#x20;   def read_file(self, path, timeout) -> CommandResult: ...\
&#x20;   def close(self) -> None: ...

Adapter نباید نام check type را hardcode کند. عملیات باید در سطح قابلیت تعریف شود؛ برای نمونه ssh.exec.readonly، config.get، file.read و device.get_version. Adapterهای Cisco، FortiGate و ESXi می‌توانند در نسخه اول از SSH استفاده کنند، اما فرمان‌ها و روش جمع‌آوری متناسب با سیستم‌عامل هدف متفاوت است.

**6.3 قرارداد Handler**

class CheckHandler(Protocol):\
&#x20;   handler_id: str\
&#x20;   supported_check_types: set[str]\
\
&#x20;   def can_handle(self, check, adapter) -> bool: ...\
&#x20;   def collect(self, check, adapter, context) -> Evidence: ...\
&#x20;   def evaluate(self, check, evidence, evaluator) -> Evaluation: ...

ترجیح معماری: Handler فقط Evidence تولید کند و Evaluator مشترک، نتیجه را تعیین کند. اگر یک نوع Check نیازمند semantics ویژه باشد، Handler می‌تواند EvaluationStrategy مشخصی را معرفی کند، اما وضعیت‌ها همچنان از enum مرکزی استفاده می‌کنند.

**6.4 قرارداد Plugin Manifest**

plugin:\
&#x20; id: vendor.cisco.iosxe\
&#x20; version: 0.1.0\
&#x20; kind: adapter\
&#x20; platform: cisco_ios_xe\
&#x20; requires:\
&#x20;   \- transport.ssh\
&#x20; provides:\
&#x20;   \- config.get\
&#x20; compatibility:\
&#x20;   software: ">=17.0,<18.0"\
&#x20; entrypoint: package.module:CiscoIOSXEAdapter

در MVP می‌توان ابتدا از registry داخلی Python استفاده کرد و در مرحله بعد از importlib.metadata entry points برای نصب Pluginهای مستقل بهره برد. بارگذاری پویا از مسیر دلخواه یا اجرای کد داخل Audit File ممنوع است.

**7. طراحی Adapterهای نسخه اول**

| **Adapter**       | **شناسایی**                                                   | **عملیات اولیه**                                        | **ملاحظات**                                                                                 |
| ----------------- | ------------------------------------------------------------- | ------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| CiscoIOSXEAdapter | SSH، اجرای فرمان‌های شناسایی read-only و تحلیل prompt/version | دریافت running configuration و بخش‌های context موردنیاز | CONFIG_CHECK و CONFIG_CHECK_NOT به شواهد config نیاز دارند؛ دسترسی privilege مناسب لازم است |
| FortiGateAdapter  | SSH/CLI، تشخیص FortiOS و مدل                                  | دریافت config بخش موردنیاز بر اساس context              | context ممکن است با عبارت‌هایی مثل config system dns یا config system global تعریف شده باشد |
| VMwareESXiAdapter | SSH، uname -a و شناسایی VMkernel/نسخه                         | اجرای CMD_EXECهای مجاز و خواندن FILE_CONTENT_CHECK      | فرمان‌های shell باید از policy مجاز عبور کنند؛ پشتیبانی pipeline نیازمند کنترل ویژه است     |



Target Discovery باید از adapterهای کاندید استفاده کند. انتخاب صرفاً بر اساس check_type فایل یا نام فایل مجاز نیست. اگر چند Adapter نتیجه مبهم بدهند، اپراتور platform را انتخاب می‌کند و سیستم قبل از اجرای Checkها سازگاری را دوباره بررسی می‌کند.

**8. طراحی Handlerهای اولیه**

| **Handler**                  | **ورودی‌های Audit**                                   | **روش جمع‌آوری**                               | **ارزیابی**                                                          |
| ---------------------------- | ----------------------------------------------------- | ---------------------------------------------- | -------------------------------------------------------------------- |
| CiscoConfigCheckHandler      | CONFIG_CHECK، CONFIG_CHECK_NOT، context، regex و item | دریافت config و استخراج context موردنیاز       | تطبیق regex/item با قواعد مثبت یا منفی؛ ambiguity به MANUAL_REVIEW   |
| CiscoBannerCheckHandler      | BANNER_CHECK، content یا فیلدهای مرتبط                | دریافت banner login/motd از config             | مقایسه محتوا با expected؛ در صورت نیاز سازمانی/متنی به Manual Review |
| FortiGateContextRegexHandler | context، regex، expect، not_expect                    | گرفتن config مربوط به context و استخراج stanza | Regex روی context اجرا شود؛ expect/not_expect با منطق روشن و تست‌شده |
| UnixCommandHandler           | CMD_EXEC، cmd، expect، severity                       | اجرای فرمان read-only از طریق Adapter          | مقایسه خروجی با expect؛ exit code و stderr جداگانه نگهداری شود       |
| UnixFileContentHandler       | FILE_CONTENT_CHECK، file، regex/expect، is_substring  | خواندن فایل مجاز از راه دور                    | مقایسه محتوای فایل؛ مسیر و مجوز خواندن کنترل شود                     |
| UnixBannerHandler            | BANNER_CHECK                                          | خواندن banner از منبع تعریف‌شده                | در صورت نامشخص‌بودن mapping، MANUAL_REVIEW                           |



FortiGate در فایل‌های نمونه غالباً type صریح برای custom_item ندارد. Normalizer باید با check_type=FortiGate و وجود context/regex/expect نوع canonical را به FortiGateContextRegexCheck نگاشت کند. این inference باید مستند و محدود به الگوی شناخته‌شده باشد؛ اگر فیلدهای لازم وجود نداشته باشند، Check به UNSUPPORTED/UNKNOWN برود، نه اینکه نوع دلخواه حدس زده شود.

**9. Condition Engine**

ساختار IF/condition/THEN/ELSE در فایل‌های Cisco، FortiGate و ESXi مشاهده شده است. شرط‌ها باید به شکل درخت حفظ شوند. AND و OR به‌صورت short-circuit یا eager قابل پیاده‌سازی‌اند، اما تمام nodeهای ارزیابی‌شده باید ثبت شوند. برای MVP اجرای ترتیبی و ارزیابی eager برای ثبت شواهد پیشنهاد می‌شود.

شرط والد ابتدا اجرا می‌شود؛ شاخه THEN یا ELSE طبق نتیجه شرط فعال می‌شود.

Checkهای شاخه اجرا‌نشده نیز در گزارش باقی می‌مانند و status آن‌ها SKIPPED یا BLOCKED همراه با علت CONDITIONAL_BRANCH_NOT_SELECTED است.

attributeهایی مانند auto="WARNING" یا auto="FAILED" به‌عنوان policy metadata ذخیره می‌شوند؛ معنای دقیق آن‌ها باید بر اساس تست نمونه و مستندات مجاز تعیین شود.

\<report type="PASSED|WARNING"> یک directive گزارش/گروه‌بندی است و نباید بدون Evidence به‌عنوان PASS برای تک‌تک Checkها تلقی شود.

شرط تشخیص پلتفرم ESXi مانند uname -a و expect=VMkernel می‌تواند gate اجرای بقیه Audit باشد.

**10. جریان اجرای Assessment**

1\. Validate IP, audit path, permissions and file size\
2\. Parse audit -> AST -> Canonical Audit Model\
3\. Resolve variables (operator overrides + defaults)\
4\. Discover target platform / version\
5\. Select adapter and request credentials securely\
6\. Connect and validate read-only capability\
7\. Create AssessmentRun and output directory\
8\. Walk condition tree in source order\
9\. For each active check:\
&#x20;    a. dispatch handler\
&#x20;    b. collect evidence\
&#x20;    c. evaluate evidence\
&#x20;    d. persist in-memory result/attempt\
&#x20;    e. continue after recoverable check errors\
10\. Interactive review unresolved items\
11\. Generate + schema-validate JSON report\
12\. Save report and execution log; close connection

نتایج باید در طول اجرا در حافظه پایدار Run نگهداری شوند و پس از هر Check تکمیل‌شده به فایل checkpoint موقت نوشته شوند تا interruption موجب از دست رفتن کل خروجی نشود. فایل نهایی report.json فقط پس از نوشتن فایل موقت و fsync/atomic rename جایگزین شود؛ نام Run یکتا است و فایل قبلی overwrite نمی‌شود.

**11. تعامل اپراتور**

رابط نسخه اول CLI است. هر مورد unresolved جداگانه نمایش داده می‌شود: شناسه، توضیح، نوع اصلی، Expected، Evidence، خطا، Remediation و Reference. گزینه‌ها PASS، FAIL، N/A، RETRY، SKIP و ABORT هستند.

برای تصمیم دستی PASS/FAIL/N/A و نیز override خطای اجرا، justification اجباری است. RETRY یک Attempt جدید ایجاد می‌کند و Attempt قبلی را حذف نمی‌کند. SKIP وضعیت unresolved را حفظ می‌کند. ABORT اجرای باقی‌مانده را متوقف می‌کند ولی نتایج تکمیل‌شده را ذخیره می‌کند.

**12. ساختار پروژه Python**

universal_audit/\
&#x20; pyproject.toml\
&#x20; README.md\
&#x20; src/universal_audit/\
&#x20;   \_\_init\_\_.py\
&#x20;   cli/\
&#x20;     app.py\
&#x20;     prompts.py\
&#x20;   core/\
&#x20;     models.py\
&#x20;     enums.py\
&#x20;     orchestrator.py\
&#x20;     dispatcher.py\
&#x20;     condition_engine.py\
&#x20;     evaluator.py\
&#x20;     registry.py\
&#x20;     exceptions.py\
&#x20;   audit/\
&#x20;     lexer.py\
&#x20;     parser.py\
&#x20;     ast.py\
&#x20;     normalizer.py\
&#x20;     metadata.py\
&#x20;     variables.py\
&#x20;   adapters/\
&#x20;     base.py\
&#x20;     ssh_transport.py\
&#x20;     cisco_iosxe/\
&#x20;       adapter.py\
&#x20;     fortigate/\
&#x20;       adapter.py\
&#x20;     vmware_esxi/\
&#x20;       adapter.py\
&#x20;   handlers/\
&#x20;     base.py\
&#x20;     cisco_config.py\
&#x20;     cisco_banner.py\
&#x20;     fortigate_context_regex.py\
&#x20;     unix_command.py\
&#x20;     unix_file_content.py\
&#x20;     unix_banner.py\
&#x20;   reporting/\
&#x20;     report_builder.py\
&#x20;     schema.json\
&#x20;     storage.py\
&#x20;     redaction.py\
&#x20;   security/\
&#x20;     credential_provider.py\
&#x20;     command_policy.py\
&#x20;     secret_filter.py\
&#x20;   config/\
&#x20;     settings.py\
&#x20; tests/\
&#x20;   fixtures/\
&#x20;     audits/\
&#x20;   unit/\
&#x20;   integration/\
&#x20;   golden/\
&#x20; results/

**13. کتابخانه‌ها و وابستگی‌های پیشنهادی**

| **کتابخانه** | **کاربرد**                         | **وضعیت پیشنهادی**                       |
| ------------ | ---------------------------------- | ---------------------------------------- |
| Python 3.12+ | زبان و runtime                     | الزامی                                   |
| Typer        | ساخت CLI                           | پیشنهادی                                 |
| Pydantic v2  | مدل‌ها، validation و serialization | پیشنهادی                                 |
| Paramiko     | SSH client                         | پیشنهادی؛ با تنظیمات سخت‌گیرانه host key |
| Rich         | نمایش وضعیت و جدول در ترمینال      | اختیاری                                  |
| jsonschema   | اعتبارسنجی خروجی JSON              | پیشنهادی                                 |
| pytest       | Unit/Integration tests             | توسعه                                    |
| Hypothesis   | تست property-based برای Parser     | اختیاری ولی مفید                         |
| platformdirs | مسیرهای config/cache               | اختیاری                                  |



وابستگی‌ها باید در pyproject.toml با نسخه‌های محدودشده ثبت شوند. برای MVP از اجرای shell محلی یا کتابخانه‌ای که Audit را به‌عنوان کد اجرا کند استفاده نشود.

**14. امنیت و کنترل اجرای فرمان**

Audit File ورودی داده غیرقابل‌اعتماد محسوب می‌شود؛ هیچ Python، shell، template یا expression موجود در آن مستقیماً اجرا نمی‌شود.

فرمان‌های CMD_EXEC قبل از اجرا باید توسط CommandPolicy بررسی شوند. MVP فقط allowlist فرمان‌های read-only را اجرا می‌کند؛ فرمان ناشناخته به UNSUPPORTED یا MANUAL_REVIEW می‌رود.

پشتیبانی از pipe/redirect و shell metacharacterها به‌صورت پیش‌فرض غیرفعال است. اگر یک Check موجود در Audit به pipeline نیاز دارد، باید یا به چند عملیات امن تجزیه شود یا تا زمان پیاده‌سازی امن، unsupported بماند.

SSH host key باید verify شود؛ AutoAddPolicy یا پذیرش بی‌قید host key استفاده نشود.

Password از getpass یا secret provider دریافت شود؛ در log، exception و report فیلتر شود.

خروجی فرمان ممکن است شامل secret باشد؛ evidence باید طبق policy redact و محدودیت حجم داشته باشد.

فقط عملیات read-only مجاز است. نام فرمان به‌تنهایی تضمین read-only بودن نیست؛ policy باید بر اساس platform و آرگومان‌ها تصمیم بگیرد.

Audit file size، تعداد nodeها، عمق nesting، regex complexity و execution timeout محدود شوند تا از DoS و ReDoS جلوگیری شود.

**15. گزارش JSON و ذخیره‌سازی**

ساختار گزارش مطابق SRS است و علاوه بر فیلدهای نمونه، باید provenance و traceability داشته باشد.

{\
&#x20; "schema_version": "1.0",\
&#x20; "assessment": {\
&#x20;   "assessment_id": "unique-id",\
&#x20;   "started_at": "ISO-8601",\
&#x20;   "completed_at": "ISO-8601 or null",\
&#x20;   "overall_status": "COMPLETED_WITH_UNRESOLVED"\
&#x20; },\
&#x20; "device": {\
&#x20;   "ip_address": "192.0.2.10",\
&#x20;   "hostname": null,\
&#x20;   "vendor": "Cisco",\
&#x20;   "platform": "cisco_ios_xe",\
&#x20;   "software_version": null\
&#x20; },\
&#x20; "audit": {\
&#x20;   "file_name": "source.audit",\
&#x20;   "sha256": "...",\
&#x20;   "benchmark": "CIS",\
&#x20;   "benchmark_name": "Cisco IOS XE 17.x",\
&#x20;   "benchmark_version": "2.2.1",\
&#x20;   "profile": "L1"\
&#x20; },\
&#x20; "summary": {\
&#x20;   "total_checks": 0, "passed": 0, "failed": 0,\
&#x20;   "not_applicable": 0, "manual_review": 0,\
&#x20;   "errors": 0, "unsupported": 0, "unknown": 0, "skipped": 0\
&#x20; },\
&#x20; "checks": [\
&#x20;   {\
&#x20;     "check_id": "stable-id",\
&#x20;     "description": "...",\
&#x20;     "original_check_type": "CMD_EXEC",\
&#x20;     "canonical_check_type": "UNIX_COMMAND",\
&#x20;     "status": "ERROR",\
&#x20;     "execution_status": "FAILED",\
&#x20;     "result_source": "NONE",\
&#x20;     "expected": "...",\
&#x20;     "actual": null,\
&#x20;     "evidence": [],\
&#x20;     "attempts": [],\
&#x20;     "operator_decision": null,\
&#x20;     "error": {"code": "COMMAND_TIMEOUT", "message": "..."},\
&#x20;     "raw_definition": {},\
&#x20;     "source_location": {"line": 120}\
&#x20;   }\
&#x20; ]\
}

مسیر ذخیره‌سازی: results/{device-id}/{software-version}/{run-timestamp}/report.json و execution.log. device-id و version باید sanitize شوند. اگر version قابل تشخیص نباشد از unknown-version استفاده می‌شود. Benchmark version با target software version دو مفهوم جدا هستند.

**16. خطاها و سیاست بازیابی**

| **کد/وضعیت**          | **شرایط**                          | **رفتار**                                               |
| --------------------- | ---------------------------------- | ------------------------------------------------------- |
| AUDIT_PARSE_ERROR     | نحو نامعتبر یا بلوک ناقص           | توقف پیش از اتصال؛ نمایش line/column                    |
| PLATFORM_UNIDENTIFIED | تشخیص پلتفرم ممکن نیست             | درخواست انتخاب دستی؛ عدم اجرای Check ناسازگار           |
| CONNECTION_ERROR      | عدم دسترسی یا SSH failure          | عدم تبدیل به FAIL؛ امکان retry                          |
| AUTHENTICATION_FAILED | اعتبارنامه نامعتبر                 | درخواست credential مجدد؛ عدم ثبت secret                 |
| PERMISSION_DENIED     | سطح دسترسی ناکافی                  | ERROR و امکان ادامه Checkهای مستقل                      |
| UNSUPPORTED_CHECK     | Handler یا capability وجود ندارد   | UNSUPPORTED همراه raw definition                        |
| COMMAND_TIMEOUT       | مهلت اجرا تمام شده                 | ERROR؛ ادامه Checkهای مستقل                             |
| INSUFFICIENT_EVIDENCE | خروجی برای تصمیم کافی نیست         | UNKNOWN یا MANUAL_REVIEW                                |
| OPERATOR_ABORT        | اپراتور Assessment را متوقف می‌کند | ذخیره نتایج و علامت‌گذاری بقیه به‌عنوان SKIPPED/BLOCKED |



**17. راهبرد تست**

**17.1 تست Parser**

Golden test برای هر شش فایل پیوست‌شده: تعداد Checkها، metadata، profile، variables و نوع Checkها باید ثابت و قابل مقایسه باشد.

تست multiline، quote escaping، comment، بلوک تو‌در‌تو، IF/ELSE، AND/OR و فیلد ناشناخته.

تست parser باید بدون اتصال شبکه اجرا شود.

فایل malformed باید خطای قابل فهم بدهد و هیچ عملیات شبکه‌ای آغاز نکند.

**17.2 تست Handler و Evaluator**

Mock adapter برای شبیه‌سازی خروجی config، command و file.

تست مثبت/منفی Regex، expect/not_expect، CONFIG_CHECK_NOT و تطبیق banner.

تست تفکیک FAIL از ERROR و UNKNOWN.

تست timeout، permission denied، خروجی خالی و خروجی چندخطی.

تست variable substitution و مقادیر پیش‌فرض/override.

**17.3 تست یکپارچه و پذیرش**

اجرای کامل Cisco L1/L2، FortiGate L1/L2 و ESXi L1/L2 روی تجهیزات آزمایشگاهی یا شبیه‌ساز کنترل‌شده.

تأیید عدم اجرای فرمان تغییردهنده؛ ثبت تمام فرمان‌های ارسالی در test harness.

تأیید اینکه هر Check از Audit در گزارش وجود دارد، حتی اگر unsupported یا در شاخه غیرفعال باشد.

تأیید JSON با schema معتبر و عدم overwrite گزارش قبلی.

تأیید ذخیره partial result پس از ABORT یا crash کنترل‌شده.

**18. نقشه راه پیاده‌سازی**

| **مرحله**                              | **خروجی**                                                 | **معیار پایان**                              |
| -------------------------------------- | --------------------------------------------------------- | -------------------------------------------- |
| Phase 1 – Foundation                   | مدل‌های Pydantic، enumها، CLI skeleton، logging و storage | ساخت Run و تولید گزارش نمونه معتبر           |
| Phase 2 – Parser                       | Lexer/Parser/AST/Normalizer و golden tests                | پارس هر شش فایل و حفظ تمام Checkها/شرط‌ها    |
| Phase 3 – Core workflow                | Registry، dispatcher، condition engine، evaluator         | اجرای تست‌ها با mock adapter بدون شبکه       |
| Phase 4 – ESXi adapter/handlers        | SSH، CMD_EXEC امن، FILE_CONTENT_CHECK                     | اجرای موفق Checkهای پشتیبانی‌شده ESXi در lab |
| Phase 5 – Cisco adapter/handlers       | config collection و CONFIG_CHECKها                        | نتایج قابل تکرار Cisco L1/L2 در lab          |
| Phase 6 – FortiGate adapter/handlers   | context config و regex/expect                             | نتایج قابل تکرار FortiGate L1/L2 در lab      |
| Phase 7 – Interactive/report hardening | Review CLI، retry، abort، schema validation، redaction    | قبولی Acceptance Criteria نسخه اول           |



**19. تصمیم‌های طراحی و ریسک‌های باز**

| **موضوع**                | **تصمیم MVP**                                    | **ریسک/نیاز به اعتبارسنجی**                                                   |
| ------------------------ | ------------------------------------------------ | ----------------------------------------------------------------------------- |
| فرمت Audit               | Parser اختصاصی و AST؛ نه XML parser خام          | باید با نمونه‌های بیشتر از Tenable سازگاری parser سنجیده شود                  |
| FortiGate item بدون type | نگاشت بر اساس check_type و context/regex/expect  | قواعد دقیق‌تر با فایل‌های FortiGate بیشتر اعتبارسنجی شود                      |
| Cisco CONFIG_CHECK       | جمع‌آوری config و مقایسه با item/context/regex   | معنای دقیق item و regex در همه شکل‌های Audit باید با تست‌های golden تثبیت شود |
| Condition auto attribute | ذخیره به‌عنوان policy metadata در ابتدا          | معنای اجرایی دقیق auto=WARNING/FAILED هنوز نیازمند آزمون/مرجع معتبر است       |
| CMD_EXEC                 | allowlist read-only؛ موارد ناشناخته unsupported  | ممکن است بخشی از 37 فرمان ESXi L1 در MVP اولیه manual/unsupported بماند       |
| امضای فایل               | ثبت hash و اعتماد به منبع ورودی؛ عدم اجرای محتوا | اعتبارسنجی امضا در نسخه بعدی قابل افزودن است                                  |
| Chrome/IIS/SQL           | فقط معماری توسعه؛ بدون پشتیبانی اجرایی فعلی      | فایل Audit واقعی و نیازمندی اتصال برای طراحی Handler لازم است                 |



**20. معیار تکمیل MVP**

هر شش فایل Audit نمونه parse شوند و Checkها بدون حذف یا تغییر خام حفظ شوند.

هر Check به یک نوع canonical شناخته‌شده یا UNSUPPORTED نگاشت شود.

سه خانواده Adapter اولیه (Cisco، FortiGate، ESXi) با قرارداد مشترک قابل ثبت باشند.

Checkهای پشتیبانی‌شده با Evidence واقعی یا mock قابل ارزیابی باشند.

شرط‌ها و شاخه‌های اجرا‌نشده در گزارش منعکس شوند.

Review تعاملی، justification، retry، skip و abort کار کنند.

گزارش JSON schema-valid، کامل و بدون credential باشد.

خروجی در ساختار device/version/run ذخیره شود و گزارش قبلی overwrite نشود.

هیچ فرمان یا remediation تغییردهنده‌ای اجرا نشود.

**پیوست A – آمار ساختاری فایل‌های نمونه**

| **فایل**            | **تعداد item/custom_item** | **توزیع نوع صریح**                                       |
| ------------------- | -------------------------- | -------------------------------------------------------- |
| Cisco IOS XE L1     | 111                        | 95 CONFIG_CHECK؛ 13 CONFIG_CHECK_NOT؛ 3 BANNER_CHECK     |
| Cisco IOS XE L2     | 26                         | 26 CONFIG_CHECK                                          |
| FortiGate L1        | 83                         | 2 BANNER_CHECK؛ سایر custom_itemها عمدتاً بدون type صریح |
| FortiGate L2        | 35                         | type صریح در custom_itemها عموماً موجود نیست             |
| VMware ESXi L1 Unix | 52                         | 37 CMD_EXEC؛ 13 FILE_CONTENT_CHECK؛ 2 BANNER_CHECK       |
| VMware ESXi L2 Unix | 4                          | 3 CMD_EXEC؛ 1 FILE_CONTENT_CHECK                         |



این شمارش‌ها از بلوک‌های ساختاری موجود در فایل‌های بارگذاری‌شده استخراج شده‌اند؛ ممکن است تعداد nodeهای شرطی و reportها جدا از تعداد Checkها باشد.

**پیوست B – الگوی افزودن Handler جدید**

یک canonical check type جدید تعریف کنید یا نوع موجود را reuse کنید.

کلاس Handler را با قرارداد CheckHandler پیاده‌سازی کنید.

قابلیت موردنیاز را در Adapter مشخص کنید؛ از اجرای مستقیم SSH در Handler خودداری کنید.

Handler را در registry ثبت کنید و can_handle را محدود و صریح بنویسید.

تست‌های unit برای پارامترها، Evidence و evaluator اضافه کنید.

یک fixture Audit واقعی یا کوچک‌شده و golden parse test اضافه کنید.

در صورت نیاز، JSON schema را فقط به شکل backward-compatible توسعه دهید.

مستندات plugin manifest و ماتریس پشتیبانی را به‌روزرسانی کنید.