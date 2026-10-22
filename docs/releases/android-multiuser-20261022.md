# android-multiuser-20261022 — resolver tracking and smaller V2 control packets

This release includes the latest fixes on `multiuser` since `android-multiuser-20261008` for both client and server.

## Changes

- Faster Base36 encoding and decoding with the existing wire format preserved. The codec is used by the client to send and by the server to receive.
- Resolver strategies 4, 5 and 6 use a recent RTT average; strategy 6 also allocates less memory when choosing paths.
- Download polling tracks each DNS request by resolver and local socket as well as DNS ID. Each resolver gets its own timeout based on RTT and jitter, bounded between 300 ms and 30 seconds; tracking tables stay bounded during outages.
- V2 PING/PONG packets omit their unused seven-byte bodies. The DNS-format test saves 29 bytes per empty round trip with raw answers, or 31 bytes with Base64 answers. The encryption keys, nonces and full 16-byte authentication tags are unchanged.
- Includes the previously merged server fix that races a destination's addresses, preferring IPv4, instead of waiting on each address in sequence.
- Adds server executables alongside the existing Android, Windows and Linux/OpenWRT client assets, configuration examples and SHA256 checksums.

## Compatibility and validation

The V2 wire layout and data payloads are unchanged. Legacy PING/PONG bodies remain compatible. ACK duplication, setup protection, ARQ retransmission policy, compression defaults and polling intervals are preserved. Client and server can be upgraded independently; upgrade both to receive both sides' improvements.

Validation includes the full Go test suite, race checks, tampering rejection for the smaller authenticated packets, and real client/server SOCKS5 echo tests through simulated DNS paths. The weak-path tests cover 10% and 20% loss in each direction, delay and jitter, small DNS datagram limits, and recovery on the same connection after a two-second blackout. The six-resolver case retains the configured three data copies and five setup/packed-control copies.

These are simulated paths, not physical-device or public-resolver tests. In six alternating 256 KiB traffic trials, median offered IPv4+UDP bytes fell about 3.5%, but results overlapped, one run used more bytes, and two new runs were slower. This does not establish a universal reduction in carrier bills or guarantee unchanged throughput. See the reports for measurements and reproduction commands:

- [Performance](https://github.com/PoriyaVali/MasterDnsVPN/blob/android-multiuser-20261022/docs/performance-fa.md)
- [Weak networks](https://github.com/PoriyaVali/MasterDnsVPN/blob/android-multiuser-20261022/docs/weak-network-fa.md)
- [Traffic efficiency](https://github.com/PoriyaVali/MasterDnsVPN/blob/android-multiuser-20261022/docs/traffic-efficiency-fa.md)

## فایل‌ها و تغییرات اصلی

اصلاحات هستهٔ کلاینت و سرور، تطبیق زمان انتظار با هر ریزولر و کوچک‌سازی بسته‌های
کنترلی V2 در این نسخه قرار دارند. پارامترهای رمزنگاری و تعداد کپی ACK حفظ شده‌اند.
فایل‌های `mdns-*` کلاینت، `mdns-server-*` سرور و `libmdns-*.so` هستهٔ اجرایی
اندروید هستند؛ فایل APK در این مخزن ساخته نمی‌شود. تنظیمات نمونه را پیش از
استفاده با اطلاعات سرور خود تکمیل کنید. اندازه‌گیری آزمایشی به معنی تضمین
سرعت یا کاهش یکسان مصرف اینترنت روی همهٔ ریزولرها نیست.
