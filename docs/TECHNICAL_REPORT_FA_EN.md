# BugScanner — Technical Review & Roadmap

## فارسی

### خلاصه اجرایی
BugScanner در مسیر تبدیل‌شدن به یک ابزار حرفه‌ای برای ارزیابی امنیتیِ مجاز قرار دارد. این شاخه شامل adaptive rate limiting، back-pressure handling، input validation، allowlist محدوده، asset normalization، finding deduplication، risk prioritization و evidence/confidence scoring است. Scope Guard قبل از فعالیت شبکه‌ای روی هدف اصلی اعمال می‌شود و assetهای کشف‌شده خارج از محدوده را کنار می‌گذارد.

### مرحله انجام‌شده فعلی
**Adaptive Feedback Loop** اکنون به runtime اضافه شده است. این لایه از یافته‌های همین اسکن استفاده می‌کند و اگر یک test family با یافته‌ای دارای اعتماد کافی مرتبط باشد، اولویت endpointهای از قبل کشف‌شده و داخل scope را به‌صورت محدود افزایش می‌دهد.

این feedback فقط ترتیب اجرای تست‌های موجود را تغییر می‌دهد؛ هدف جدیدی اضافه نمی‌کند، scope را گسترش نمی‌دهد، payload جدید تولید نمی‌کند و رفتار stealth/bypass ندارد. داده target-specific نیز بین اسکن‌ها ذخیره نمی‌شود.

### زنجیره فعلی
`Target Validation → Scope Guard → Asset Inventory → Discovery → Context Planner → Adaptive Feedback → Budgeted Tests → FP Validation → Deduplication → Evidence/Confidence → Risk Prioritization → Reporting`

### مرحله قبل
**Evidence & Confidence Engine** برای هر finding فیلدهای `evidence_quality`، `confidence`، `independent_confirmations` و `verification_status` را محاسبه می‌کند. این metadata قبل از risk prioritization اعمال می‌شود.

### نکته فنی مهم
`independent_confirmations` در پیاده‌سازی فعلی هنوز باید دقیق‌تر شود تا فقط تأییدهای واقعاً مستقل را بشمارد؛ در گام بعد بهتر است provenance بر اساس scanner/source/method متمایز شود و صرفاً تعداد رکوردهای تکراری مبنای تأیید نباشد.

### پیشنهادهای فنی بعدی
1. **Evidence Provenance:** منبع مستقل هر evidence را ثبت و شمارش confirmation را بر اساس source/method متمایز کن.
2. **Persistent Aggregate Feedback:** پس از provenance، یک پروفایل aggregate و غیرحساس برای نتایج تاریخی اضافه شود؛ بدون URL/secret/credential و بدون امکان override کردن scope.
3. **Request Budget:** برای هر asset و test family بودجه درخواست مستقل تعریف شود.
4. **Safe Back-pressure:** منطق WAF با نام `evasion` به adaptive throttling، Retry-After و کاهش فشار شبکه محدود شود.
5. **Reporting:** گزارش JSON/HTML/PDF با executive summary، scope، coverage، findings، evidence، confidence و remediation تولید شود.
6. **CI Quality Gates:** unit tests، lint، type checking و security regression در GitHub Actions اجرا شوند.
7. **Configuration Validation:** scope و rate limit در startup schema-validation شوند.

### معیارهای موفقیت
- صفر request خارج از scope در regression.
- deterministic بودن planner، feedback و risk ranking.
- هر finding دارای evidence و confidence باشد.
- feedback فقط روی attack surface از قبل کشف‌شده اثر بگذارد.
- هیچ داده حساس target در feedback history ذخیره نشود.

### ملاحظات امنیتی
این پروژه باید فقط روی دارایی‌هایی اجرا شود که مجوز ارزیابی آن‌ها وجود دارد. Scope Guard باید fail-closed بماند و discovery یا feedback نباید scope را به‌صورت خودکار گسترش دهد.

---

## English

### Executive Summary
BugScanner is progressing toward a professional tool for authorized security assessment. This branch includes adaptive rate limiting, back-pressure handling, input validation, explicit scope allowlisting, asset normalization, finding deduplication, deterministic risk prioritization, and evidence/confidence scoring.

### Current Stage
An **Adaptive Feedback Loop** is now integrated into runtime orchestration. It uses findings from the current scan to apply a small, deterministic priority boost when an already-planned test family is supported by a sufficiently trusted finding family.

The feedback loop only reorders existing in-scope work. It does not discover new targets, expand authorization boundaries, generate bypass payloads, or persist target-specific data between scans.

### Current Pipeline
`Target Validation → Scope Guard → Asset Inventory → Discovery → Context Planner → Adaptive Feedback → Budgeted Tests → FP Validation → Deduplication → Evidence/Confidence → Risk Prioritization → Reporting`

### Previous Stage
The **Evidence & Confidence Engine** adds `evidence_quality`, `confidence`, `independent_confirmations`, and `verification_status` to findings before risk prioritization.

### Important Technical Note
The current `independent_confirmations` field still needs stronger provenance semantics. The next hardening step should distinguish genuinely independent scanner/source/method evidence from repeated records of the same fingerprint.

### Recommended Next Steps
1. **Evidence Provenance:** Track independent evidence sources and base confirmation counts on distinct source/method identities.
2. **Persistent Aggregate Feedback:** After provenance is hardened, introduce a bounded aggregate historical profile containing no URLs, secrets, credentials, or scope overrides.
3. **Request Budgets:** Add per-asset and per-test-family request budgets.
4. **Safe Back-pressure:** Replace legacy WAF `evasion` behavior/terminology with respectful adaptive throttling and Retry-After handling.
5. **Professional Reporting:** Produce JSON/HTML/PDF reports with scope, coverage, findings, evidence, confidence, and remediation.
6. **CI Quality Gates:** Add unit tests, linting, type checks, and security regression coverage.
7. **Configuration Validation:** Validate scope and rate-limit settings at startup.

### Success Criteria
- Zero out-of-scope requests in regression tests.
- Deterministic planner, feedback, and risk ranking.
- Every finding has evidence and confidence metadata.
- Feedback only affects already-discovered attack surface.
- No sensitive target data is retained in feedback history.

### Security Considerations
Use the project only against assets for which assessment authorization exists. Scope Guard must remain fail-closed, and discovery or feedback must never silently expand the authorization boundary.
