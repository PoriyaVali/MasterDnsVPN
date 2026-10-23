# android-multiuser-20261023 — PR #7 recovery and SOCKS UDP ownership fixes

Includes all fixes from `android-multiuser-20261022` and merges [PR #7](https://github.com/PoriyaVali/MasterDnsVPN/pull/7).

## New fixes

- A single-server client restarts a session after requests go unanswered for 45 seconds. Consecutive failed recoveries back off from one to five minutes, and every second failed recovery measures the resolvers again. A real inbound packet, rather than runtime startup, resets the failure count. Pool members remain supervised by the pool.
- SOCKS5 UDP associations bind to the TCP connection's local interface and accept only the owning TCP peer's IP and declared or first valid UDP port. Invalid datagrams cannot claim the association. The relay closes with the control connection or context.

## Compatibility

The network protocol, session keys and complete authentication tags are unchanged. These PR #7 fixes run in the client; updating only V2bX does not add them to an older app core. Old V2 clients can continue to use the new server while the app upgrade is prepared. V2bX's existing protocol acceptance policy is preserved.

Actual Linux client binaries from `android-multiuser-20260928`, `android-multiuser-20261008` and `android-multiuser-20261022` were exercised against the current public server package used by V2bX, with V2 required by the client. Each completed three 24,690-byte downloads, including one after the node restarted and lost its old sessions. Random application data was compared byte-for-byte and the server's encrypted downstream was checked. The compatibility test can be repeated with an external previous-release executable:

```sh
MDNS_COMPAT_CLIENT=/absolute/path/to/mdns-linux-amd64 \
  go test -race ./server -run '^TestE2EOlderClient$' -count=1 -v -timeout 2m
```

This tests the core protocol on local sockets, not an Android device. When updating the core inside Doctor Mobile, include the separate app-side recovery handling described in PR #7: initialization failures during a running session must not be treated as a startup that never succeeded. That app change is outside these MDNS and V2bX releases.

## Files

Android core executables, Windows and Linux/OpenWRT clients and servers, configuration examples, and per-platform SHA256 checksum files. No APK is built here. The [previous traffic report](https://github.com/PoriyaVali/MasterDnsVPN/blob/android-multiuser-20261023/docs/traffic-efficiency-fa.md) still applies: measured savings and throughput vary by workload and resolver.

## فارسی

اصلاحات PR شمارهٔ ۷ شامل بازیابی نشست تک‌سروری و محدودکردن UDP در SOCKS به
صاحب اتصال TCP ادغام شده‌اند. نسخه‌های قبلی V2 می‌توانند به سرور جدید متصل شوند؛
ارتقای V2bX را می‌توان پیش از ارتقای هستهٔ اپ انجام داد. قابلیت بازیابی جدید و
اصلاح SOCKS سمت کاربر، پس از ارتقای هستهٔ همان کاربر فعال می‌شوند. هنگام ارتقای
خود اپ، اصلاح مربوط به تشخیص خطای شروع سرویس نیز باید همراه هسته اعمال شود.
