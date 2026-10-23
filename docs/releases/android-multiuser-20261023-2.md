# android-multiuser-20261023-2 — faster recovery of a burst's first lost packet

Includes everything in `android-multiuser-20261023` and merges [PR #8](https://github.com/PoriyaVali/MasterDnsVPN/pull/8).

## Changes

- **Retransmission timing (client and server).** A stream starts on the configured 1 s RTO until its first round trip is measured. Packets queued in that first instant — an upload, a page's first request — kept the 1 s timer even after the path had been measured at a fraction of it, so a packet lost at the end of the burst held the stream for about a second. A first transmission now waits on the current measured RTO when that is shorter (RFC 6298 §5.3); a retransmission keeps its backoff, and timers only get shorter. The measured RTO keeps its existing floor.
- **Stall watch.** The 45-second single-server recovery (and the pool's per-server restart) now waits at least three pings at the current ping pace, so a quiet tunnel with a long `PING_COLD_INTERVAL_SECONDS` is not restarted over one lost ping. With the default settings the wait stays 45 s.
- **Resolver selection.** Resetting or re-seeding a resolver's stats also clears its recent RTT average, so a resolver re-enabled after a recheck is judged on new samples rather than the slow ones from before it was disabled.
- Tests only: the weak-network profiles run in parallel; the SOCKS UDP tests skip where `127.0.0.2` cannot be bound (macOS).

## Compatibility and validation

The wire protocol, session keys and authentication are unchanged; older clients and servers keep working with this release. The retransmission change is in the shared ARQ package, so the server side only gets it when V2bX embeds this release.

Measured on local sockets (from the commit, 12 runs): TestTrafficEfficiency median 1.35 s → 0.60 s, max 2.71 s → 1.03 s; TestPerf at 60 ms / 2 % loss, download 136 → 173 KiB/s and parallel 133 → 192 KiB/s. These are simulated paths, not phone or public-resolver results.

Before release: `go vet ./...` clean, `go test ./...` passing (22 packages), `go test -race` on `internal/arq` and `internal/client` passing, and GitHub Go Test plus all ten platform builds green on the merged branch.

## فارسی

بسته‌های اولِ هر اتصال (مثل اولین درخواست یک صفحه) اگر گم شوند، حالا زودتر دوباره
فرستاده می‌شوند، به‌جای اینکه یک ثانیه کامل منتظر بمانند. بازیابی خودکار نشست روی
اتصال‌های کم‌کار زودتر از موعد اجرا نمی‌شود. انتخاب ریزولر پس از فعال‌شدن دوباره،
بر اساس اندازه‌گیری تازه انجام می‌شود. پروتکل و کلیدها تغییری نکرده‌اند؛ برای بخش
سرور باید V2bX هم این نسخه را بگیرد.
