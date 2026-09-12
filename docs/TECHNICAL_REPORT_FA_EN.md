# BugScanner — Technical Review, Reporting & Roadmap

## فارسی

### گزارش فنی و وضعیت فعلی
BugScanner اکنون علاوه بر pipeline اصلی اسکن، یک لایه گزارش‌دهی فنی مبتنی بر evidence دارد. نتیجه اسکن شامل scope/asset coverage، subdomain، port، endpoint، severity، CVSS، evidence، remediation، confidence و verification status است.

### زنجیره فعلی
`Target Validation → Scope Guard → Asset Inventory → Discovery → Context Planner → Adaptive Feedback → Budgeted Tests → FP Validation → Deduplication → Evidence/Confidence → Risk Prioritization → Technical Reporting`

### Evidence & Confidence
هر finding دارای `evidence_quality`، `confidence`، `independent_confirmations` و `verification_status` است. این metadata قبل از risk prioritization تولید می‌شود. Confidence از evidence، payload، reproduction material، exploitation evidence، parameter context، references و confirmation count ساخته می‌شود.

### Adaptive Feedback
Adaptive Feedback از یافته‌های همین اسکن برای افزایش محدود priority تست‌های از قبل برنامه‌ریزی‌شده استفاده می‌کند. این حلقه scope را گسترش نمی‌دهد، هدف جدید کشف نمی‌کند، payload bypass تولید نمی‌کند و داده target-specific را بین اسکن‌ها ذخیره نمی‌کند.

### Reporting
گزارش HTML به یک **Technical Security Assessment Report** کامل‌تر ارتقا یافته است و شامل این بخش‌هاست:
- Executive Summary
- Severity Distribution و Risk Score
- Assessment Coverage
- Discovered Assets / Subdomains / Open Ports
- Findings با CVSS و Verification Status
- Confidence و Evidence Quality
- Parameter / Method / CWE
- Evidence و Validation/PoC details
- Payload و cURL reproduction request در صورت وجود
- Remediation و References
- Methodology و Limitations

گزارش JSON نیز metadata فنی findingها را از طریق `Vulnerability.to_dict()` نگه می‌دارد. مدل فعلی شامل evidence quality، confidence، confirmation count و verification status است.

### اصلاح اخیر Reporter
مشکل filename روی Windows نیز اصلاح شده است. URLهایی که query string دارند دیگر مستقیماً نام فایل نمی‌شوند؛ کاراکترهای نامعتبر sanitize می‌شوند، reserved Windows names مدیریت می‌شوند و برای نام‌های طولانی hash کوتاه اضافه می‌شود.

### نکته فنی مهم
`independent_confirmations` هنوز باید از نظر provenance دقیق‌تر شود؛ تعداد رکوردهای مشابه نباید به‌تنهایی معادل تأیید مستقل تلقی شود. مرحله بعد باید source/scanner/method identity را جدا کند.

### مراحل بعدی پیشنهادی
1. Evidence Provenance واقعی بر اساس source/scanner/method.
2. Request Budget مستقل برای asset و test family.
3. Aggregate historical feedback بدون URL، secret، credential یا scope override.
4. Safe back-pressure و حذف/بازتعریف کامل رفتارهای legacy با نام `evasion` به سمت throttling و Retry-After.
5. PDF reporting در کنار JSON/HTML.
6. CI quality gates شامل unit tests، lint، type checking و security regression.
7. Startup configuration/schema validation.

### معیارهای موفقیت
- صفر request خارج از scope در regression.
- planner، feedback و risk ranking کاملاً deterministic.
- هر finding دارای evidence و confidence قابل ممیزی باشد.
- feedback فقط روی attack surface از قبل کشف‌شده اثر بگذارد.
- هیچ داده حساس target در feedback history ذخیره نشود.
- report generation حتی برای targetهای دارای query string روی Windows fail نکند.

### ملاحظات امنیتی
BugScanner باید فقط روی دارایی‌های دارای مجوز اجرا شود. Scope Guard باید fail-closed بماند و discovery یا feedback نباید authorization boundary را خودکار گسترش دهد.

---

## English

### Technical Status
BugScanner now includes an evidence-oriented technical reporting layer on top of the scanning pipeline. Scan results expose scope/asset coverage, subdomains, ports, endpoints, severity, CVSS, evidence, remediation, confidence, and verification status.

### Current Pipeline
`Target Validation → Scope Guard → Asset Inventory → Discovery → Context Planner → Adaptive Feedback → Budgeted Tests → FP Validation → Deduplication → Evidence/Confidence → Risk Prioritization → Technical Reporting`

### Evidence & Confidence
Each finding carries `evidence_quality`, `confidence`, `independent_confirmations`, and `verification_status`. These fields are computed before risk prioritization. The confidence model uses collected evidence, payload presence, reproduction material, exploitation evidence, parameter context, references, and confirmation count.

### Adaptive Feedback
Adaptive Feedback uses findings from the current scan to apply a bounded priority boost to already-planned tests. It does not discover new targets, expand authorization boundaries, generate bypass payloads, or persist target-specific data between scans.

### Professional Technical Reporting
The HTML output has been upgraded into a **Technical Security Assessment Report** containing:
- Executive Summary
- Severity Distribution and Risk Score
- Assessment Coverage
- Discovered Assets, Subdomains, and Open Ports
- Detailed Findings with CVSS and Verification Status
- Confidence and Evidence Quality
- Parameter, Method, and CWE metadata
- Evidence and Validation/PoC details
- Payload and cURL reproduction material when available
- Remediation and References
- Methodology and Limitations

The JSON report preserves the same technical finding metadata through `Vulnerability.to_dict()`. The current model explicitly serializes evidence quality, confidence, confirmation count, and verification status. fileciteturn105file0

### Reporter Reliability Fix
Report generation was hardened for Windows-compatible filenames. URLs containing query strings are no longer used as raw filenames; invalid filename characters are sanitized, reserved Windows device names are handled, and long names receive a deterministic short hash. This prevents a completed scan from failing during report persistence because of URL-derived filename characters. fileciteturn108file0

### Important Technical Note
`independent_confirmations` still needs stronger provenance semantics. A count of repeated records should not automatically be treated as independent confirmation. The next hardening step should distinguish evidence by scanner/source/method identity.

### Next Engineering Steps
1. **Evidence Provenance:** Track independent evidence sources using scanner/source/method identities.
2. **Request Budgets:** Add bounded request budgets per asset and test family.
3. **Historical Aggregate Feedback:** Add a non-sensitive aggregate profile containing no URLs, secrets, credentials, or scope overrides.
4. **Safe Back-pressure:** Replace legacy WAF `evasion` terminology/behavior with respectful throttling and Retry-After handling.
5. **PDF Reporting:** Add a PDF export alongside JSON and HTML.
6. **CI Quality Gates:** Add unit tests, linting, type checking, and security regression coverage.
7. **Startup Validation:** Validate scope and rate-limit configuration before scanning begins.

### Success Criteria
- Zero out-of-scope requests in regression testing.
- Deterministic planner, feedback loop, and risk ranking.
- Every retained finding has auditable evidence and confidence metadata.
- Feedback only affects the attack surface already discovered in the authorized scope.
- No sensitive target data is retained in feedback history.
- Report generation remains reliable for URL targets containing query strings on Windows.

### Security Considerations
BugScanner must only be used against assets for which assessment authorization exists. Scope Guard must remain fail-closed, and discovery or feedback must never silently expand the authorization boundary. The current runtime applies adaptive feedback after endpoint discovery and before the planned endpoint tests are executed. fileciteturn115file0
