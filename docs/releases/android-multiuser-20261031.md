# android-multiuser-20261031 — lower server CPU per byte

Includes everything in `android-multiuser-20261023-2` and merges [PR #9](https://github.com/PoriyaVali/MasterDnsVPN/pull/9).

## Changes

- **Server CPU per byte.** The node spends 6–16 % less CPU for each MiB it carries, depending on direction and cores; throughput and latency are unchanged. The method, the profiles and the reasoning behind each change are in [docs/server-cpu-fa.md](https://github.com/PoriyaVali/MasterDnsVPN/blob/android-multiuser-20261031/docs/server-cpu-fa.md).
  - **DNS names:** a query name is measured, then built in one allocation of the exact size; capitals fold on the stack; an answer compares the question's name in place instead of parsing it again.
  - **Client addresses:** read without allocations, with the IP text built only when it is needed. It is the same text as before, so the panel's device counts do not change.
  - **ARQ NACKs:** for an out-of-order packet the decisions are taken under one lock and without allocations, and the prune is skipped when it cannot remove anything. On upload, the NACK code's share of node CPU went from 5.0 % to 3.7 %.
  - **Stream state:** `IsClosed` and `IsReset`, asked for every packet, no longer take the stream's lock.
  - **DNS workers** read their queue without selecting on the shutdown channel for each packet.
- **Client.** It shares the DNS parser and ARQ packages, so it gets the same changes; its behaviour is unchanged.
- **Benchmark.** `scripts/bench/cpu` runs the node the way V2bX embeds it and drives it with the real client in the Android app's balanced profile through simulated resolvers, reading the node's CPU per phase and checking every byte.
- **Releases.** `publish-dm.yml` publishes an `android-*` draft once Go Test has passed on the tag's commit and every file in both SHA256SUMS lists is attached with that checksum. The notes are this file.

## Compatibility and validation

The packet format, encryption, session keys, authentication and ARQ behaviour are unchanged; older clients and servers keep working with this release, and clients need no update for the server's gains. V2bX nodes get them when V2bX embeds this release; the `mdns-server-*` binaries here have them already.

Node CPU per MiB on loopback, with four simulated resolvers 10 ms away, ChaCha20 and a 4-core Xeon at 2.1 GHz; mean of alternating runs, lower is better:

| Node cores | Download | Upload |
| --- | ---: | ---: |
| 4 | 101.6 → 91.2 ms (−10.2 %) | 244.1 → 215.6 ms (−11.7 %) |
| 2 | 89.7 → 82.5 ms (−8.0 %) | 231.7 → 195.8 ms (−15.5 %) |
| 1 | 77.0 → 72.5 ms (−5.8 %) | 205.0 → 183.3 ms (−10.6 %) |

Download stayed at about 1.88 MiB/s. Upload throughput varies 6–12 % from run to run in both versions and did not change beyond that. Round trips stayed at 222.5 ms on an open stream and 122 ms on a new connection (p50). These are simulated paths on loopback, not phones or public resolvers.

On servers: the node asks for 8 MB socket buffers, but Linux caps them at `net.core.rmem_max` (often about 200 KB). Running `sysctl -w net.core.rmem_max=8388608 net.core.wmem_max=8388608`, and saving it under `/etc/sysctl.d/`, lets the setting apply.

Before release: `go vet ./...` clean, `go test ./...` passing (23 packages), `go test -race` on `internal/arq`, `internal/udpserver`, `internal/dnsparser` and `internal/domainmatcher` passing, and GitHub Go Test plus all ten platform builds green on the branch.

## فارسی

مصرف CPU سرور برای هر مگابایت ترافیک، بسته به جهت و تعداد هسته‌ها، ۶ تا ۱۶ درصد
کم شده است؛ سرعت و تأخیر تغییری نکرده‌اند. قالب بسته، رمزنگاری و احراز هویت همان
است و کلاینت‌های قبلی بدون به‌روزرسانی کار می‌کنند. نودهای V2bX این بهبود را وقتی
می‌گیرند که V2bX این نسخه را در خود بگیرد؛ باینری‌های `mdns-server-*` همین انتشار
آن را دارند. روش اندازه‌گیری و جزئیات در
[گزارش کاهش مصرف CPU سرور](https://github.com/PoriyaVali/MasterDnsVPN/blob/android-multiuser-20261031/docs/server-cpu-fa.md)
آمده است.

برای اینکه بافر ۸ مگابایتی سوکت سرور واقعاً اعمال شود، این را روی سرور اجرا کنید
و در `/etc/sysctl.d/` هم ذخیره کنید:

```sh
sysctl -w net.core.rmem_max=8388608 net.core.wmem_max=8388608
```
