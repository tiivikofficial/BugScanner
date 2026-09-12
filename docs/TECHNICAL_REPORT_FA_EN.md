# BugScanner — Technical Review & Roadmap

## فارسی

### خلاصه اجرایی
BugScanner در مسیر تبدیل‌شدن به یک ابزار حرفه‌ای برای ارزیابی امنیتیِ مجاز قرار دارد. در این مرحله، کنترل نرخ درخواست، واکنش به back-pressure، اعتبارسنجی ورودی، allowlist محدوده، نرمال‌سازی assetها، حذف یافته‌های تکراری و اولویت‌بندی ریسک به هسته اضافه شده‌اند. Scope Guard اکنون قبل از فعالیت شبکه‌ای روی هدف اصلی اعمال می‌شود و assetهای کشف‌شده خارج از محدوده را کنار می‌گذارد.

### مرحله انجام‌شده فعلی
**Adaptive Vulnerability Test Planning** به‌عنوان لایه تصمیم‌گیری اضافه شده است. این لایه URLهای موجود را بر اساس مسیر و پارامترهای شناخته‌شده دسته‌بندی می‌کند و تست‌های مرتبط مانند XSS، SQLi، SSRF، Redirect و IDOR را با اولویت مشخص پیشنهاد می‌دهد. هدف، کاهش تست‌های غیرمرتبط و افزایش تمرکز روی attack surface موجود است.

### نکته فنی مهم
در نسخه فعلی، planner و Scope Guard وجود دارند و تست‌های واحد برای آن‌ها اضافه شده‌اند؛ اما planner هنوز به‌طور کامل جایگزین اجرای مستقیم همه scannerها در orchestration اصلی نشده است. این باید مرحله بعدی باشد تا رفتار adaptive واقعاً در runtime اعمال شود.

### پیشنهادهای فنی اولویت‌دار
1. **Runtime Orchestration:** خروجی `VulnerabilityOrchestrator` مستقیماً به اجرای scannerها متصل شود؛ فقط تست‌های مرتبط اجرا شوند و fallback امن برای baseline باقی بماند.
2. **Evidence Engine:** برای هر finding، request/response خلاصه‌شده، status code، headerهای مرتبط، پارامتر، زمان و confidence ذخیره شود؛ بدون ذخیره secrets یا credentialها.
3. **Finding Confidence:** علاوه بر severity و CVSS، confidence جداگانه تعریف شود تا یافته‌های مشکوک با یافته‌های تأییدشده قاطی نشوند.
4. **Asset Graph:** رابطه domain → subdomain → endpoint → parameter → finding به‌صورت graph نگهداری شود تا attack surface قابل تحلیل باشد.
5. **Request Budget:** برای هر asset و هر test family بودجه درخواست مستقل تعریف شود؛ این کار از مصرف بی‌رویه منابع جلوگیری می‌کند.
6. **Safe Back-pressure:** منطق WAF فعلی که نام `evasion` دارد بازطراحی شود و صرفاً به adaptive throttling، Retry-After و کاهش فشار شبکه محدود بماند.
7. **Authenticated Roles:** برای محیط‌های مجاز، role/sessionهای تعریف‌شده به‌صورت explicit وارد شوند و مقایسه دسترسی‌ها با diff کنترل‌شده انجام شود.
8. **Reporting:** گزارش JSON/HTML/PDF با executive summary، scope، coverage، findings، evidence، confidence، remediation و timeline تولید شود.
9. **CI Quality Gates:** تست واحد، lint، type checking و security regression در GitHub Actions اجرا شوند.
10. **Configuration Validation:** تنظیمات scope و rate limit در startup schema-validation شوند تا misconfiguration باعث scan ناخواسته نشود.

### معماری پیشنهادی نهایی
`Target Validation → Scope Guard → Asset Inventory → Discovery → Context Planner → Budgeted Tests → Evidence/Confidence → Deduplication → Risk Prioritization → Reporting`

### معیارهای موفقیت
- صفر request خارج از scope در تست‌های regression.
- کاهش معنی‌دار تست‌های نامرتبط نسبت به اجرای همه scannerها.
- هر finding دارای evidence و confidence باشد.
- deterministic بودن fingerprint و risk ranking.
- تولید گزارش قابل استفاده برای تیم فنی و مدیر امنیت.

### ملاحظات امنیتی
این پروژه باید فقط روی دارایی‌هایی اجرا شود که مجوز ارزیابی آن‌ها وجود دارد. Scope Guard باید fail-closed بماند و discovery نباید scope را به‌صورت خودکار گسترش دهد.

---

## English

### Executive Summary
BugScanner is progressing toward a professional tool for authorized security assessment. The current branch includes adaptive request throttling, back-pressure handling, input validation, explicit scope allowlisting, asset normalization, finding deduplication, and deterministic risk prioritization. Scope Guard now validates the root target before network activity and filters discovered assets outside the configured scope.

### Current Stage
An **Adaptive Vulnerability Test Planner** has been added. It classifies already-discovered URLs using path and parameter context and proposes relevant checks such as XSS, SQLi, SSRF, Redirect, and IDOR with deterministic priorities. The purpose is to reduce irrelevant testing and focus effort on meaningful attack surface.

### Important Technical Note
The planner and Scope Guard now exist and have unit-test coverage, but the planner is not yet the sole runtime decision point for scanner execution. The next implementation step should wire the planner into the main orchestration path so adaptive selection actually controls which test families run.

### High-value Engineering Recommendations
1. **Runtime Orchestration:** Connect `VulnerabilityOrchestrator` directly to scanner execution and retain a safe baseline fallback.
2. **Evidence Engine:** Store concise request/response evidence, status code, relevant headers, parameter, timing, and confidence without retaining secrets or credentials.
3. **Finding Confidence:** Track confidence independently from severity/CVSS so suspected findings are clearly separated from confirmed findings.
4. **Asset Graph:** Model domain → subdomain → endpoint → parameter → finding relationships for attack-surface analysis.
5. **Request Budgets:** Apply per-asset and per-test-family request budgets to prevent uncontrolled resource consumption.
6. **Safe Back-pressure:** Refactor legacy WAF `evasion` terminology and behavior toward adaptive throttling, Retry-After handling, and respectful network pressure only.
7. **Authenticated Roles:** For explicitly authorized environments, support declared sessions/roles and controlled authorization-diff testing.
8. **Professional Reporting:** Produce JSON/HTML/PDF reports containing executive summary, scope, coverage, findings, evidence, confidence, remediation, and timeline.
9. **CI Quality Gates:** Add unit tests, linting, type checks, and security regression tests to GitHub Actions.
10. **Configuration Validation:** Validate scope and rate-limit configuration at startup so misconfiguration cannot silently expand scan behavior.

### Recommended Final Architecture
`Target Validation → Scope Guard → Asset Inventory → Discovery → Context Planner → Budgeted Tests → Evidence/Confidence → Deduplication → Risk Prioritization → Reporting`

### Success Criteria
- Zero out-of-scope requests in regression tests.
- Material reduction in irrelevant tests compared with full scanner execution.
- Every finding has evidence and confidence metadata.
- Deterministic finding fingerprints and risk ranking.
- Reports usable by both engineering and security leadership.

### Security Considerations
The project should only be used against assets for which assessment authorization exists. Scope Guard should remain fail-closed, and discovery must never silently expand the configured authorization boundary.
