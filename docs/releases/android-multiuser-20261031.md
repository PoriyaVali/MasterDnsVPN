# android-multiuser-20261031 — server CPU optimizations and safer session startup

Includes `android-multiuser-20261023-2`, the server CPU optimizations from
[PR #9](https://github.com/PoriyaVali/MasterDnsVPN/pull/9), and the release-readiness
corrections described below. Claude authored PR #9; Codex prepared this release
and the subsequent session/benchmark corrections.

## Changes

- **Server:** fewer DNS-name and client-address allocations, fewer ARQ NACK
  lock acquisitions, atomic reads of frequently queried stream state, and a
  lower-cost DNS-worker receive loop. Subscriber metering, device accounting,
  encryption, authentication and the packet format are preserved.
- **Client session startup:** concurrent session attempts finish before an
  accepted server policy mutates client configuration. A valid early response
  can finish startup without waiting for every staggered attempt to launch;
  losing exchanges are cancelled and joined.
- **CPU benchmark:** simulated resolvers use independent IP addresses so the
  client retains every path. The driver validates path use and rejects failed,
  corrupt or incomplete transfers. The earlier stdout/stderr capture race is
  also fixed.
- **Validation:** Go Test includes vet, client/server package race checks and a
  real-client, four-resolver smoke run on Linux. Release publication still
  requires passing Go Test on the exact tagged commit and complete matching
  Android/desktop checksum manifests.

## What the performance numbers mean

PR #9 reported approximately 6–16% lower server CPU per MiB with unchanged
throughput and latency. Its original fixture declared four resolvers on one IP;
the client removed duplicate IPs, leaving one effective path and one effective
copy. Those historical numbers describe that single-path workload. They are
not a new result for the corrected multipath benchmark, a server-capacity
guarantee or a prediction for public resolvers. See
[the corrected methodology](https://github.com/PoriyaVali/MasterDnsVPN/blob/android-multiuser-20261031/docs/server-cpu-fa.md).

## Deployment and compatibility

Existing clients remain compatible with the server CPU changes. Embedded nodes
must be rebuilt against this source; replacing a standalone `mdns-server-*`
file does not change the MDNS code inside V2bX. The companion V2bX release pins
this source so operators can receive it through the normal V2bX updater.

Android, desktop/router clients and standalone servers are built from the same
immutable tag. The new client startup changes require updating the client
binary; existing clients can still use the updated server.

## Known limitation

A resolver that starts returning empty DNS NOERROR answers can still be scored
as healthy by the existing client balancer and stall useful traffic. That
preexisting path-health issue is separate from the session-startup race fixed
here; this release does not redesign resolver health scoring or adaptive pacing.

## فارسی

این نسخه بهینه‌سازی‌های CPU سرور در PR #9 را همراه با اصلاح race آغاز نشست
کلاینت منتشر می‌کند. قالب بسته، رمزنگاری و احراز هویت تغییر نکرده‌اند.

ابزار سنجش قبلی به‌دلیل حذف IP تکراری عملاً تک‌مسیره بود؛ بنابراین اعداد قبلی
کاهش ۶ تا ۱۶ درصدی CPU فقط به همان بار محدودند. ابزار اصلاح شده است، اما برای
شبکهٔ واقعی یا حالت چندمسیره درصد بهبود تازه‌ای تضمین نمی‌شود.

برای اعمال بهینه‌سازی روی نودهایی که با V2bX کار می‌کنند، V2bX باید با این
نسخه دوباره ساخته شود. انتشار همراه V2bX همین وابستگی را ارتقا می‌دهد و از
طریق updater معمول آن قابل دریافت خواهد بود.
