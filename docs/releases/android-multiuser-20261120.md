# android-multiuser-20261120 — faster resolver switching that holds up when every resolver is slow

Includes `android-multiuser-20261031` and PRs #10 to #14. Most changes are in
the client's resolver balancing. The client now leaves a failing resolver
faster and lets a recovered one back in. It also keeps working when every
resolver is under load and answers late, as on a throttled national network.
Claude authored PRs #10 to #14.

## Changes

### Client: switching between resolvers

- **A silent resolver is counted lost within its own round trip** (#13). The
  timeout is the resolver's average plus four deviations, at least 600 ms. A
  250 ms sweep collects the losses. The balancer now moves off a dead path in
  about a second, instead of 5–10 s.
- **A NOERROR reply without the tunnel's TXT answer is a failure** (#11). This
  is a resolver that strips, filters or truncates the answer. Before, it counted
  as a success, and least-loss balancing kept every query on a path that
  delivered nothing. This fixes the known limitation listed in
  `android-multiuser-20261031`.
- **Duplicate copies are no longer cut** (#14). Strategies 6, 7 and 8 took every
  copy from their candidate pool alone. Strategy 6 sent one copy whenever one
  resolver was clearly the fastest; 7 and 8 sent two at most. The remaining
  copies now go to the other resolvers, by loss and then by round trip.
- **The top tier of strategies 7 and 8 ranks the faster first within the loss
  band of the best**, then by loss (#14). The tier keeps its size, so load
  stays spread when every resolver slows down at once.
- **Idle resolvers are probed and old losses fade** (#14). Probes are polls to
  the resolver idle longest. They go every 3 s while no downstream data
  arrives; otherwise after 15 s, doubling to 60 s per unanswered probe. After
  15 s without a loss, each answer halves a resolver's old losses. A resolver
  that recovers comes back into use.

### Client: slow and poor resolvers

- **A resolver is never disabled just because its answers are late** (#14).
  Auto-disable counts only queries unanswered past the request timeout, and
  never sooner than 5 s. The request timeout falls to 1 s past 75 resolvers.
  Before, a burst of a dozen queries to a resolver answering in 2.5 s disabled
  it.
- **The client connects when every resolver answers in seconds** (#14). When
  fewer than three resolvers pass the MTU scan, the others get a patient pass
  at three times the probe timeout (4–8 s). Before, the client rescanned with
  the same timeout forever. Rechecks now wait at least 4 s per probe, and
  session init at least 6 s.
- **Losses are counted with `AUTO_DISABLE_TIMEOUT_SERVERS` off** (#14). The
  setting now only decides whether a resolver may be disabled.

### Server

- **Requests are queued by pointer** (#10). This ends the request-queue memory
  regression of `android-multiuser-20261031`.

## Measured

The setup is a local harness, not committed. It runs a real node and four
resolvers on their own loopback addresses, at 20/35/50/70 ms one way. The
busiest resolver fails mid-stream. Figures are medians. These are not
guarantees for public resolvers.

| Scenario | 20261031 + #10–#13 | This release |
|---|---|---|
| Strategy 6, three copies, bulk | 227 KiB/s | 436 KiB/s |
| Strategy 6, bulk with a slow resolver | 14 KiB/s | 252 KiB/s |
| Strategy 8, worst stall with a resolver that drops answers | 1.28 s | 0.54 s |
| Throttled profile, excess delay with a slow resolver | 3.46 s | 0.62 s |

We also simulated a throttled national network: every resolver at once got
+600 ms, up to 1.5 s of jitter and 8% loss each way. No resolver was disabled,
and all four stayed in use.

`server/slow_resolvers_e2e_test.go` has every resolver answer in 3.4 s, with
`MTU_TEST_TIMEOUT` set to 1 s. The client connects in about 18 s; before this
release it never connected.

## Deployment and compatibility

The packet format, encryption and authentication are unchanged. Existing
servers work with this client, and this server works with existing clients.
No configuration key was added or removed.

The client behaves differently in three ways:

- Auto-disable is more conservative.
- Idle resolvers get an occasional poll.
- When resolvers are slow, startup takes longer instead of failing.

The server change (#10) needs a server rebuild. Embedded nodes take it when
they are rebuilt against this source.

## فارسی

این نسخه بیشتر تغییرهای سمت کلاینت را دارد:

- کلاینت از ریزولور خراب در حدود یک ثانیه جابه‌جا می‌شود.
- ریزولوری که فقط دیر جواب می‌دهد، کمتر از ۵ ثانیه انتظار غیرفعال نمی‌شود.
- اگر همهٔ ریزولورها کند باشند، کلاینت با آزمون صبورتر (۴ تا ۸ ثانیه) باز هم
  وصل می‌شود.
- تعداد کپی‌ها همان است که تنظیم شده.
- ریزولوری که خوب شود دوباره به کار گرفته می‌شود.

قالب بسته، رمزنگاری و احراز هویت تغییر نکرده‌اند. سرور و کلاینت با نسخه‌های
قبلی سازگارند.
