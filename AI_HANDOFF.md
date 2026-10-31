# AI work log and handoff

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
