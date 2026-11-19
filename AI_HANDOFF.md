# AI work log and handoff

## Active handoff - 2026-11-19 - Claude - client: a silent resolver is counted lost by its own round trip

Measured first, with a real node and four resolvers on their own loopback
addresses (local harness, not committed), the busiest failing mid-stream.
An unanswered query counted as lost only after the request timeout - the
auto-disable check interval, 5 s with up to five resolvers - and the health
loop collected those once per interval, so a dead resolver kept a clean
record for 5-10 s and the tunnel's retransmissions backed off behind it.

Change (internal/client/balancer.go, mtu.go, client.go): each resolver's
loss timeout is its RTT average plus four deviations (TCP's timer; deviation
now tracked beside rttEWMA), at least 600 ms, at most the old request
timeout; `runResolverLossSweep` collects what is due every 250 ms (the
health loop still collects too; a sample is counted once). The late-answer
grace stays on the request timeout, so a resolver that is only slow gets its
loss retracted.

Measured (worst stall / time degraded, before -> after): one copy, strategy
8, silent: 1.9 s / 10.8 s -> 1.8 s / 2.7 s; one copy, strategy 6, silent:
11.9 s -> 1.1 s; strategy 6, three copies, slow resolver: 12 s degraded ->
2 s; nothing got worse. Strategies 3 and 8 still never avoid a resolver that
is only slow (latency is not in their score). Tests:
internal/client/loss_timeout_test.go, server/resolver_switch_e2e_test.go
(old code 11.5-13.5 s, new 0.9-3.5 s, threshold 6 s). go test ./... and the
CI race set pass (go1.25.0, Linux).

## Active handoff - 2026-11-19 - Claude - flaky TCP server test fixed

`TestServerAnswersPipelinedQueriesOverTCP` failed once in CI ("no TCP
listener: connection refused", 0.00s) on PR #11, whose diff did not touch
internal/udpserver. Cause: `runTestServer` returns as soon as UDP answers,
and `Run` opens the TCP listener just after starting the UDP readers, so a
dial in between is refused. Reproduced every time with a 50 ms delay before
the TCP listen (local only, not committed); the tests now dial through
`dialTCP`, which retries for up to 2 s, and pass with the delay in place.
Test-only change (internal/udpserver/server_tcp_test.go).

## Active handoff - 2026-11-19 - Claude - client: empty NOERROR answers count as failures (the known path-health stall)

Fixes the stall recorded below as known and unfixed. In a session the server
answers every query with a TXT record (queued data or a PONG); a NOERROR reply
without one comes from a resolver that stripped, filtered or truncated it.
`handleInboundPacket` (internal/client/async_runtime.go) credited it as a
resolver success, with the shortest RTT and no loss, so least-loss balancing
(strategy 3, the default, and 6) kept every query on the path that delivers
nothing. It is now a resolver failure (`TrackResolverFailure`: loss, and
auto-disable may take the path out until a recheck finds it carrying the
tunnel). A parsed but untrusted packet is no longer credited either. Server
empty answers in a session are protocol errors only (checked:
server_ingress.go, validatePostSessionPacket, handlePostSessionPacket).

Tests: internal/client/empty_answer_test.go (balancer pick with strategies 3,
6 and 8; one failure per empty answer) and
server/empty_answer_e2e_test.go (real node, two resolvers, the fast one turns
empty mid-stream). Before: 0 of 21 bytes in 6 s, ~68 empty replies, strategies
3 and 6; after: delivered in 0.4-1.0 s. Strategy 8 rotates over both of two
resolvers and delivered before and after. The superseded
`TestHandleInboundPacketTreatsMissingTXTAsResolverSuccess` is removed.
`go test ./...` and the CI race set pass locally (go1.25.0, Linux).

Not changed (measured by Codex 2026-10-31, tuning without real-network data):
pull depth, MTU minimum across fewer than five paths, duplication counts.
Known: the confirm-down probe behind auto-disable runs on the processor worker
that saw the failure, as SERVFAIL already did (4-20 active resolvers only).

## Active handoff - 2026-10-31 - Codex - android-multiuser-20261031 PUBLIC and verified

RELEASED stable/latest at 2026-10-31T18:25:42Z:
https://github.com/PoriyaVali/MasterDnsVPN/releases/tag/android-multiuser-20261031
Immutable annotated tag/source 1a73a5ad59f492addb7a85e61c3761a02921968b.
Claude PR9 optimizations retained with attribution; Codex release corrections
are in1a73a5a. This follow-up changes ONLY AI_HANDOFF.md and is documentation,
not a new runtime revision for this release; do not move the tag.

ACTUAL hosted validation: GoTest41228850772 and tagGoTest41229193871 SUCCESS
(full Linux tests,vet,client/server package race and real2client4resolver smoke).
Smoke JSON verified4independent paths all carrying bidirectional traffic,
524288verifiedbytes each bulk direction,20RTTs,8newconnections,zeroerrors or
corrupt payloads. This is correctness evidence, not a corrected CPU speedup.
Android41229193868 and Desktop/server41229193873 SUCCESS. Guarded publication
41229353241 SUCCESS after exact-sourceGoTest and both checksum manifests.

All22publicassets/nonzero sizes and SHA256 manifests verified independently.
Downloaded Windows client/server hashes match, -version prints release tag,
and Go metadata shows exact source1a73a5a/vcs.modified=false. Full receipts
stored in parent hiddify-app/.dart_tool/mdns-v2bx-release-20261031/. No node
installation/restart; owner will use companion V2bX updater themselves.

V2bX integration source5d72b9cee70c56823af1f2333f8976601f52db67 pins this exact
MDNS module, targetv1.12.1; workflow41229434022 running mandatory validation
and release builds at this checkpoint (not yet public). Shared root handoff
will record final V2bX publication. Known preexisting empty-NOERROR path-health
stall remains documented, not fixed. No universal6-16%/capacity claim.

## Active handoff - 2026-10-31 - Codex - release candidate validated locally; Linux CI/publication PENDING

UNCOMMITTED release candidate includes Claude PR9 server CPU changes and Codex
fixes below. Existing empty-NOERROR resolver-health stall is NOT FIXED; it is
prominent in release notes. No new universal CPU%, capacity or phone/network
claim. No production server deployment requested or performed.

Exact Codex-authored files:
- internal/client/session.go, internal/client/tunnel_runtime.go,
  internal/client/session_race_test.go: init event loop handles early responses,
  captures pool capacity, validates accept/busy before cancellation, cancels and
  joins racers before changing policy; socket cancellation callback is joined
  before ownership can return to the pool. No wire/crypto/auth changes.
- scripts/bench/cpu/drv/main.go, validation.go, validation_test.go: independent
  127.0.0.N relay IPs; actual config parsed count and INFO MTU-valid count;
  byte-exact warmup + aggregate per-path traffic; byte/sample/error/corruption
  failures produce nonzero exit with child cleanup; /proc failure is fatal.
  Duplication fields are configured upper caps, not observed copy ratios.
- docs/server-cpu-fa.md, scripts/bench/README.md: historical6-16% CPU results
  explicitly scoped to one effective path/copy; no corrected benchmark claim.
- .github/workflows/go-test.yml: vet, runtime package -race and two-real-client/
  four-path Linux smoke with preserved JSON artifact.
- docs/releases/android-multiuser-20261031.md and AI_HANDOFF.md: corrected notes,
  attribution, compatibility, known limitation and publication checkpoints.

Validation ACTUALLY RUN before commit:
- go test ./... -count=1 -timeout=10m PASS on Windows Go1.25.12.
- go vet ./... PASS.
- -race client/arq/udpserver/dnsparser/domainmatcher PASS.
- New focused session/policy/cancellation regressions -race -count5 PASS2.192s.
- Prior unique-IP real V2 E2E -race -count3 PASS18.941s, zero race warnings.
  Temp server/release_validation_research_test.go removed after run, not shipped.
  Empty-DNS stall remains0/21bytes for3s and restores byte-exact, as documented.
- Portable driver helpers (benchcheck) normal/race tests PASS; Linux amd64
  driver and test-binary crossbuild PASS. These are not Linux runtime execution.
- YAML parse, gofmt and git diff --check PASS. Independent cross-reviews found
  no confirmed blocking regression. Original bad combined delete/add patch
  rejected before mutation; sequential replacement succeeded.

Linux full tests/smoke and release builds/checksum publication still PENDING.
Source commit/tag and actual publication receipts recorded in later entries.
No commits or remote mutations yet at this checkpoint.

## Active handoff - 2026-10-31 - Codex - release preparation IN PROGRESS

Owner authorizes a new MasterDnsVPN release and embedding it into a new V2bX
release consumable by `v2bx update`. Isolated source starts at multiuser merge
dd6ed9046300fc51729a47772e91ce8fb7749aac. Claude authored upstream PR #9 CPU
optimizations; Codex owns this release preparation and forthcoming safety fixes.

Known unresolved preexisting client handshake config race must be fixed and
tested before release. CPU harness currently collapses four same-IP relay
endpoints into one due resolver IP deduplication, and does not fail on transfer
errors. Correct harness and scope reported CPU claims; do not invent speedups.
Do not alter cryptography, packet format, subscriber accounting or resolver
dedup policy to improve benchmark numbers.

Exact files so far: AI_HANDOFF.md (new, uncommitted). Code, validation, source
commit, immutable release tag, binary checksums and public release pending.
No live node deployment or user VPN interruption planned. Shared parent
hiddify-app/AI_HANDOFF.md retains the preceding investigation and release log.
