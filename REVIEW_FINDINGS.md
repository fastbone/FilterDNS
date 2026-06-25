# REVIEW_FINDINGS.md

## Summary

FilterDNS is a single .NET console DNS proxy. It pulls zones from an upstream master over AXFR, rewrites SOA/NS records, optionally filters private A/AAAA data, stores file-backed zone history, then serves AXFR/IXFR to slaves and ACL-gated health-check queries. The highest-risk paths are DNS wire parsing, ACL/range matching, zone history persistence, IXFR diffing, and cache-update side effects. The codebase builds cleanly, but several normal DNS scenarios can still produce corrupt transfers, refused transfers, or silent operational failures.

Total findings: 19

- Critical: 3
- High: 6
- Medium: 8
- Low: 2

Fix first:

1. Fix persisted history RDATA loss before trusting IXFR after restart.
2. Replace the shared CIDR matcher before relying on whitelists or private-IP filtering.
3. Fix IXFR/RRset diff identity so duplicate records and TTL changes are not lost.
4. Normalize zone names at configuration load so mixed-case zones do not break external DNS paths.
5. Remove cache-update side effects from health checks and transfer-triggered refreshes.

### Critical Fix Progress

- [x] **SEV-01:** Fixed in this branch. Added persisted raw RDATA round-trip coverage in `FilterDns.Tests/CriticalFindingTests.cs`.
- [x] **SEV-02:** Fixed in this branch. Added diff coverage for TTL-only changes and loaded same-name A records with distinct RDATA.
- [x] **SEV-03:** Fixed in this branch. Added CIDR coverage for non-byte-aligned IPv4 whitelist ranges and custom IPv6 private ranges.
- [ ] **SEV-04+ follow-ups:** Not started in this pass.

## Findings

### [SEV-01] Persisted history drops RDATA and can corrupt IXFR after restart

- **Severity:** Critical
- **Status:** Fixed in this branch
- **Confidence:** Confirmed
- **Location:** `FilterDns/Cache/ZoneHistoryStorage.cs:26-34`, `FilterDns/Cache/ZoneHistoryStorage.cs:481-530`, `FilterDns/Dns/IxfrResponseBuilder.cs:378-455`
- **What's wrong:** JSON history declares `RawRdataBase64`, but `ConvertToJson` never writes it and `ConvertFromJson` restores `OriginalRecord = null`. `IxfrResponseBuilder.SerializeRdataWithoutCompression` returns empty RDATA when a loaded non-SOA/non-NS record has no `OriginalRecord`.
- **How it manifests:** After restart, persisted A, AAAA, MX, TXT, CNAME, SRV, PTR, CAA, and unknown record versions cannot be serialized correctly in IXFR. Slaves requesting IXFR from old persisted serials can receive malformed records or record deletions even though in-memory history worked before restart.
- **Fix instructions:** In `ZoneHistoryStorage`, persist canonical RDATA for every `FilteredRecord`. Add fields or a raw base64 payload that round-trips all served record types. In `ConvertFromJson`, restore enough type-specific data for `RecordComparer` and `IxfrResponseBuilder` to serialize identical RDATA. If a legacy history file lacks RDATA, mark that zone history unsafe for IXFR and force AXFR until rebuilt. Add a regression test that saves and reloads a zone with A, AAAA, MX, TXT, CNAME, CAA, SOA, and NS records, then builds an IXFR and asserts every RDATA length and payload is non-empty and correct.
- **Risk / blast radius:** Touches history file format, IXFR serialization, diffing, and any existing persisted files. Coordinate with [SEV-02] because both affect record identity.
- **Depends on:** none

### [SEV-02] IXFR diff keys collapse duplicate RRsets and omit TTL changes

- **Severity:** Critical
- **Status:** Fixed in this branch
- **Confidence:** Confirmed
- **Location:** `FilterDns/Cache/RecordComparer.cs:43-52`, `FilterDns/Cache/RecordComparer.cs:119-128`, `FilterDns/Cache/RecordComparer.cs:154-172`, `FilterDns/Cache/RecordComparer.cs:227-239`, `FilterDns/Xfer/ZoneDiffCalculator.cs:45-80`
- **What's wrong:** `ZoneDiffCalculator` uses one dictionary entry per record key. When `OriginalRecord` is null, A/AAAA and unknown-type RDATA hashes become the hash of an empty string, so multiple records at the same owner/type/class collapse into one key. TTL is not included in equality or keys, so TTL-only updates are invisible.
- **How it manifests:** Round-robin A/AAAA, multiple MX/TXT values, or loaded history records can be dropped from IXFR diffs. A record with only a TTL change is never sent as delete+add, so slaves keep stale TTLs until AXFR.
- **Fix instructions:** Redesign record identity as a multiset over canonical owner, type, class, TTL, and canonical RDATA. Do not store duplicate RRset members in a single dictionary value; count duplicates or store lists per key. Update `RecordComparer.RecordsEqual` and `GetRecordKey` to use the same canonical data as IXFR serialization. Add tests for two A records on one name, two MX records with different exchanges, same RDATA with changed TTL, and records loaded from persisted history.
- **Risk / blast radius:** Changes IXFR output for all record types and depends on accurate RDATA persistence from [SEV-01].
- **Depends on:** [SEV-01]

### [SEV-03] Custom CIDR matching breaks ACLs and private-IP filtering

- **Severity:** Critical
- **Status:** Fixed in this branch
- **Confidence:** Confirmed
- **Location:** `FilterDns/Filter/RecordFilter.cs:195-204`, `FilterDns/Filter/RecordFilter.cs:223-272`, `FilterDns/Whitelist/IpWhitelist.cs:10-27`, `FilterDns/Whitelist/IpWhitelist.cs:52-81`
- **What's wrong:** Both `RecordFilter` and `IpWhitelist` compute `(prefixLength + 7) / 8`, compare that many full bytes, then also read the next byte for partial prefixes. Non-byte-aligned prefixes such as `/25`, `/17`, `/7`, and `/10` are evaluated incorrectly; exact network addresses can hit `IndexOutOfRangeException`. Invalid prefix lengths are accepted.
- **How it manifests:** Whitelisted clients inside valid CIDRs can be denied transfers or health checks. Custom private ranges can fail to match private records, leaking internal addresses into public zones. A probe against `192.168.1.0/25` confirmed `192.168.1.1` is denied and `192.168.1.0` throws.
- **Fix instructions:** Replace both implementations with one tested CIDR helper. Compare `prefixLength / 8` full bytes, then mask only the remaining bits in the last partial byte. Validate prefix ranges as 0-32 for IPv4 and 0-128 for IPv6, and reject address-family mismatches. Normalize IPv4-mapped IPv6 addresses before matching. Add tests for `/0`, `/8`, `/12`, `/17`, `/25`, `/32`, `/7`, `/10`, `/64`, `/128`, invalid negative prefixes, and too-large prefixes.
- **Risk / blast radius:** Affects XFER whitelist, health-check ACL, and custom private-IP filtering. Existing deployments with broken CIDRs may change behavior immediately.
- **Depends on:** none

### [SEV-04] Hardened DNS compression parsing leaves the offset at the pointed-to name

- **Severity:** High
- **Confidence:** Confirmed
- **Location:** `FilterDns/Dns/DnsMessageParser.cs:334-368`, `FilterDns/Dns/DnsMessageParser.cs:414-417`
- **What's wrong:** In the hardening branch of `ReadDomainName`, compression pointers are followed, but `jumped` and `jumpOffset` are never set. After resolving a compressed name, the caller resumes reading at the target name terminator instead of after the original two-byte pointer.
- **How it manifests:** Normal compressed DNS records are misparsed. A minimal IXFR-style authority SOA with owner `C0 0C` parsed as record type `IXFR` instead of `SOA`, so client serial extraction returned null and would fall back to AXFR.
- **Fix instructions:** In the hardening branch, on the first pointer, set `jumpOffset = offset + 1` and `jumped = true` before following the pointer. Continue loop-depth validation as now, and after name completion restore `offset = jumpOffset`. Add parser tests for compressed question references in answer, authority, and additional sections, including IXFR authority SOA serial extraction.
- **Risk / blast radius:** Central DNS parser used by UDP NOTIFY, health checks, TCP transfers, and NOTIFY response parsing.
- **Depends on:** none

### [SEV-05] Mixed-case configured zone names break NOTIFY, transfers, and health checks

- **Severity:** High
- **Confidence:** Confirmed
- **Location:** `FilterDns/Proxy/DnsProxyServer.cs:107-115`, `FilterDns/Xfer/XferHandler.cs:665-676`, `FilterDns/Xfer/XferHandler.cs:771-783`, `FilterDns/Xfer/XferHandler.cs:942-965`
- **What's wrong:** `_zones`, `_notifySenders`, and `_zoneUpdateSemaphores` are keyed with `zoneConfig.Name` exactly as configured. External request paths lower-case query names before lookup. A configured `Example.com` key is not found for `example.com`.
- **How it manifests:** Polling may work internally while AXFR/IXFR requests are refused as unknown zone, upstream NOTIFY is ignored, and health checks return NXDOMAIN.
- **Fix instructions:** Add one canonical-zone-name helper used at configuration load and every lookup: trim trailing dot, lower-case invariant, and consider IDNA if intended. Store `_zones`, `_notifySenders`, `_zoneUpdateSemaphores`, cache keys, and history keys using the canonical value. Preserve display names only for logs/config. Add tests with `Zones[].Name = "Example.COM."` and requests for `example.com` and `www.example.com`.
- **Risk / blast radius:** Touches all dictionaries keyed by zone name plus on-disk history filenames. Coordinate with migration behavior for existing mixed-case history files.
- **Depends on:** none

### [SEV-06] Health-check cache misses update history and notify slaves

- **Severity:** High
- **Confidence:** Confirmed
- **Location:** `FilterDns/Xfer/XferHandler.cs:803-824`, `FilterDns/Xfer/XferHandler.cs:1400-1443`, `FilterDns/Proxy/DnsProxyServer.cs:340-380`
- **What's wrong:** A health-check query from an allowed IP fetches upstream on cache miss, then calls `UpdateCacheAndNotifyAsync`. That callback updates history and sends NOTIFY to all slaves, even though the trigger was only a read-style health probe.
- **How it manifests:** A load balancer or monitor can trigger upstream AXFRs, zone history writes, and slave NOTIFY storms after startup or cache eviction. Slaves can initiate transfers because a health check asked for one record.
- **Fix instructions:** Split cache population from propagation. For health checks, fetch and filter data only for the response or populate cache without calling `onZoneUpdatedDuringTransfer` and without NOTIFY. If cache population is desired, serialize it through the same per-zone update lock and only notify slaves when an actual upstream poll/authorized NOTIFY detects a serial change. Add a test that clears cache, runs one health-check query, and asserts no `NotifySender.NotifyAllAsync` call occurs.
- **Risk / blast radius:** Touches health check behavior, cache warmup, and notification semantics.
- **Depends on:** none

### [SEV-07] Transfer-triggered refreshes race poll/NOTIFY updates and notify slaves mid-transfer

- **Severity:** High
- **Confidence:** Confirmed
- **Location:** `FilterDns/Proxy/DnsProxyServer.cs:516-531`, `FilterDns/Xfer/XferHandler.cs:1001-1036`, `FilterDns/Xfer/XferHandler.cs:1071-1105`, `FilterDns/Xfer/XferHandler.cs:1400-1443`
- **What's wrong:** Poll and upstream-NOTIFY updates are serialized by `_zoneUpdateSemaphores`, but inbound AXFR/IXFR refreshes call `UpdateCacheAndNotifyAsync` without that lock. They also notify all slaves while the requesting slave may still be in the middle of its transfer.
- **How it manifests:** Concurrent transfer, poll, and upstream NOTIFY paths can double-fetch, update cache/history out of order, create duplicate NOTIFYs, or send slaves into competing transfers. This is most likely during rapid serial changes or cold cache.
- **Fix instructions:** Route all cache/history mutations through one per-zone update service or semaphore shared by `DnsProxyServer` and `XferHandler`. Add a trigger reason parameter so slave-transfer refreshes can update cache/history without immediate NOTIFY, or can schedule debounced NOTIFY after the initiating transfer completes. Add a concurrency test with one transfer-triggered refresh and one poll update and assert serial/history order is deterministic.
- **Risk / blast radius:** Affects update orchestration, history consistency, NOTIFY timing, and slave synchronization.
- **Depends on:** none

### [SEV-08] IXFR calculates diffs from live history after validating a snapshot

- **Severity:** High
- **Confidence:** Confirmed
- **Location:** `FilterDns/Xfer/XferHandler.cs:1552-1613`, `FilterDns/Xfer/ZoneDiffCalculator.cs:95-110`
- **What's wrong:** `HandleIxfrRequestAsync` snapshots history for validation, but then passes the live `ZoneHistory` to `ZoneDiffCalculator.CalculateDiffSequence`. Concurrent adds/prunes/saves can change the versions used for the actual diff after validation succeeds.
- **How it manifests:** Under concurrent updates, IXFR can be built from a different history set than the one validated. Slaves may receive missing, extra, or inconsistent diff sequences, or fall back intermittently.
- **Fix instructions:** Change `CalculateDiffSequence` to accept an immutable `Dictionary<uint, ZoneVersion>` snapshot or a list of copied versions. Ensure both validation and diff calculation use the same snapshot and copied record lists. Add a test that mutates live history after validation but before diff calculation and asserts IXFR output still uses the original snapshot.
- **Risk / blast radius:** IXFR behavior and history APIs. This complements [SEV-07] but can be fixed independently inside the IXFR read path.
- **Depends on:** none

### [SEV-09] Minimum record count is enforced after cache, history, and NOTIFY

- **Severity:** High
- **Confidence:** Confirmed
- **Location:** `FilterDns/Proxy/DnsProxyServer.cs:627-699`, `FilterDns/Xfer/XferHandler.cs:1178-1200`
- **What's wrong:** Poll/NOTIFY refreshes cache filtered records and notify slaves without applying `MinimumZoneRecordCount`. The minimum is only checked later when a slave requests a transfer.
- **How it manifests:** With `MinimumZoneRecordCount = 10`, the proxy can cache a 3-record zone, notify slaves, then refuse the slave transfer. Verification may clear history and resend NOTIFY, but the transfer remains refused, creating a stuck recovery loop.
- **Fix instructions:** Enforce `MinimumZoneRecordCount` before cache update, history update, NOTIFY, and verification scheduling. If a fetched filtered zone is below the configured minimum, keep the last good cache, do not notify slaves, report a zone failure, and serve the previous good zone or REFUSED according to policy. Add tests for below-minimum startup fetch, poll update, NOTIFY-triggered update, and transfer-triggered refresh.
- **Risk / blast radius:** Changes reliability behavior for intentionally tiny zones; allow `0` to disable as documented.
- **Depends on:** none

### [SEV-10] CAA records are serialized with an invalid extra value-length byte

- **Severity:** Medium
- **Confidence:** Confirmed
- **Location:** `FilterDns/Dns/DnsRecordBuilder.cs:377-399`, `FilterDns/Dns/IxfrResponseBuilder.cs:437-445`
- **What's wrong:** RFC 6844 CAA RDATA is `flags`, `tag length`, `tag`, then `value` as the remaining bytes. Both serializers add an extra `value length` byte before the value.
- **How it manifests:** AXFR, IXFR, and health-check answers containing CAA records are not wire-compatible. Slaves or validators may reject or misread CAA policy.
- **Fix instructions:** Remove the extra `data.Add((byte)valueBytes.Length)` from both CAA serializers. Update comments to state that only the tag is length-prefixed. Add a wire-format test for `0 issue "letsencrypt.org"` and assert the RDATA bytes are `00 05 69 73 73 75 65 ...` with no value-length octet.
- **Risk / blast radius:** Affects only CAA output; update any tests that encoded the old behavior.
- **Depends on:** none

### [SEV-11] AXFR size limit can abort after sending a partial transfer

- **Severity:** Medium
- **Confidence:** Confirmed
- **Location:** `FilterDns/Xfer/XferHandler.cs:1207-1230`, `FilterDns/Xfer/XferHandler.cs:1261-1308`
- **What's wrong:** There is a rough pre-check based on `recordCount * 100`, then exact byte checks while streaming. If the exact count exceeds `MaxZoneTransferSizeBytes` after the opening SOA or a later record, the method returns without sending a DNS error or a complete trailing SOA.
- **How it manifests:** Slaves receive an incomplete AXFR stream and may hang, retry, or install no zone. Logs show an abort, but the client sees a truncated transfer rather than a clean refusal.
- **Fix instructions:** Compute exact transfer size before writing any AXFR messages, or refuse before streaming when the configured limit would be exceeded. If exact precomputation is too expensive, remove the mid-stream partial-send path and prefer conservative pre-refusal. Add a test with a low size limit and assert the first response is REFUSED or SERVFAIL with no partial SOA/record stream.
- **Risk / blast radius:** Affects very large zones and defensive limits.
- **Depends on:** none

### [SEV-12] NOTIFY receive sends NOERROR before validating zone and source

- **Severity:** Medium
- **Confidence:** Confirmed
- **Location:** `FilterDns/Xfer/XferHandler.cs:658-676`, `FilterDns/Xfer/XferHandler.cs:680-735`
- **What's wrong:** The UDP NOTIFY handler sends `NoError` immediately for any SOA NOTIFY question, then checks whether the zone exists and whether the sender matches the configured upstream.
- **How it manifests:** Unauthorized or unknown-zone NOTIFY senders receive a successful DNS response even though the proxy ignores the update. An upstream with a source-address mismatch may believe the proxy accepted the NOTIFY.
- **Fix instructions:** First select the zone, validate source address, and decide the response code. Send exactly one response per NOTIFY message. Use `Refused` or `NotAuth`-equivalent policy for unauthorized/unknown zones, and `NoError` only after acceptance. Add tests for valid upstream, wrong upstream, unknown zone, and multiple SOA questions.
- **Risk / blast radius:** Changes DNS response behavior for NOTIFY clients.
- **Depends on:** [SEV-05]

### [SEV-13] UDP concurrency limiting silently drops DNS packets

- **Severity:** Medium
- **Confidence:** Confirmed
- **Location:** `FilterDns/Xfer/XferHandler.cs:215-229`
- **What's wrong:** When `MaxConcurrentUdpRequests` is saturated, the server logs and `continue`s without any DNS response.
- **How it manifests:** Health checks time out instead of receiving SERVFAIL/REFUSED. NOTIFY senders see packet loss and may retry in bursts, worsening load.
- **Fix instructions:** For parseable DNS packets, send a minimal `ServFail` or `Refused` response using the request ID before dropping work. If parsing is too expensive under saturation, document an intentional drop policy and exempt health-check/NOTIFY response expectations. Add a load test that saturates the semaphore and asserts clients receive deterministic DNS errors.
- **Risk / blast radius:** Affects overload behavior and monitoring reliability.
- **Depends on:** none

### [SEV-14] Verification mismatch recovery does not schedule a retry check

- **Severity:** Medium
- **Confidence:** Confirmed
- **Location:** `FilterDns/Verify/SlaveVerificationService.cs:110-146`, `FilterDns/Verify/SlaveVerificationService.cs:181-187`
- **What's wrong:** On mismatch within retry budget, the service may clear history and resend NOTIFY, then exits. It does not schedule another delayed verification for the same expected serial. The retry counter only advances if a later external `ScheduleVerification` call happens.
- **How it manifests:** If the zone is quiet after a mismatch, slaves can remain wrong indefinitely even though logs say retry attempt N of M.
- **Fix instructions:** After re-NOTIFY, schedule a delayed verification for the same zone/serial/record count with backoff until success or `maxRetries`. Keep one pending verification per zone and cancel/replace it only when a newer serial is scheduled. Add tests where the first verification mismatches, the second succeeds, and no new zone update occurs.
- **Risk / blast radius:** Affects recovery timing and NOTIFY volume.
- **Depends on:** none

### [SEV-15] Self-restart verification and window-limit config is not wired

- **Severity:** Medium
- **Confidence:** Confirmed
- **Location:** `FilterDns/Config/Configuration.cs:82-118`, `FilterDns/Recovery/SelfRestartService.cs:70-87`, `FilterDns/Recovery/SelfRestartService.cs:146-205`
- **What's wrong:** `MaxRestartsInWindow` and `RestartWindowSeconds` are configured but never enforced. `ReportVerificationFailure` implements per-zone verification failure counting, but no verification code calls it.
- **How it manifests:** A flapping service can restart indefinitely after uptime threshold. Per-zone verification failure thresholds do not work as described; only a later `ReportCriticalError` path can contribute to restart logic.
- **Fix instructions:** Persist or otherwise track restart timestamps across process exits, then enforce `MaxRestartsInWindow` within `RestartWindowSeconds` before `Environment.Exit`. Call `ReportVerificationFailure` from slave verification mismatch paths or remove the unused config/API and document the actual behavior. Add tests for restart suppression after N restarts and for verification mismatch triggering the configured threshold.
- **Risk / blast radius:** Affects operational recovery and service-manager behavior.
- **Depends on:** none

### [SEV-16] Startup/export configuration validation misses important contract checks

- **Severity:** Medium
- **Confidence:** Confirmed
- **Location:** `FilterDns/Program.cs:47-65`, `FilterDns/Program.cs:148-196`, `FilterDns/Program.cs:223-256`, `FilterDns/Upstream/UpstreamClient.cs:14-20`
- **What's wrong:** Server startup validation only checks zones, `Ns1`/`Ns2`, and zone-name syntax. Export skips validation entirely. Invalid log levels throw `Enum.Parse` exceptions, malformed upstream/listen addresses fail later, duplicate zones overwrite silently, and invalid private ranges can silently keep records public.
- **How it manifests:** Misconfiguration is discovered at runtime with unclear exceptions or masked behavior. `export` can run with config that the server would reject, and it uses the CLI zone spelling for upstream fetch/filtering instead of the canonical configured name.
- **Fix instructions:** Create a shared validator used by both server and export. Validate log levels with `Enum.TryParse`, upstream as host/IP plus port, listen address/port, `IxfrResponseMode`, duplicate canonical zone names, email required fields, slave ports, whitelist entries, and private ranges. After export zone lookup, use `zoneConfig.Name` for fetch/filter/export. Add negative config tests for each invalid field and assert the error names the bad key.
- **Risk / blast radius:** Startup behavior becomes stricter; may reject configs that previously limped along.
- **Depends on:** [SEV-03], [SEV-05]

### [SEV-17] History save can mutate live history and replace files non-atomically

- **Severity:** Medium
- **Confidence:** Confirmed
- **Location:** `FilterDns/Cache/ZoneHistoryStorage.cs:281-291`, `FilterDns/Cache/ZoneHistoryStorage.cs:339-347`, `FilterDns/Cache/ZoneHistory.cs:143-176`
- **What's wrong:** `SaveAsync` prunes the live `ZoneHistory` object as a side effect, while `UpdateZoneHistoryAsync` already prunes by effective history depth. The disk replace deletes the old file before moving the temp file into place.
- **How it manifests:** A save can remove versions during a concurrent IXFR read. A crash between delete and move leaves no valid JSON history file, losing IXFR history on restart.
- **Fix instructions:** Make `SaveAsync` serialize a copied/pruned view rather than mutating the live history. Keep pruning ownership in one place. Replace files atomically with `File.Replace` when a target exists, or with a same-directory atomic move that never deletes the last valid file first. Add tests for saving while history has more than max versions and for simulated replace failure preserving the old file.
- **Risk / blast radius:** Affects persistence, retention, and IXFR availability.
- **Depends on:** none

### [SEV-18] Path containment and symlink checks fail open in storage hardening

- **Severity:** Low
- **Confidence:** Confirmed
- **Location:** `FilterDns/Cache/ZoneHistoryStorage.cs:190-215`, `FilterDns/Cache/ZoneHistoryStorage.cs:221-240`
- **What's wrong:** `ValidatePathWithinDirectory` uses a plain string prefix check, so `/var/filterdns/data-backup/file` starts with `/var/filterdns/data`. `IsSymlink` returns false if attribute inspection fails.
- **How it manifests:** Security hardening can accept paths outside the intended directory in prefix-collision layouts and can fail open when symlink metadata cannot be read.
- **Fix instructions:** Normalize base and target with `Path.GetFullPath`, ensure the base path has a trailing separator, and compare with path-segment boundaries. If symlink inspection fails under hardening, fail closed. Add tests for sibling-prefix paths, symlink files, symlink directories, and inspection exceptions.
- **Risk / blast radius:** Mostly affects hardened file-operation guarantees and unusual filesystem layouts.
- **Depends on:** none

### [SEV-19] Critical paths have no automated tests

- **Severity:** Low
- **Confidence:** Confirmed
- **Location:** `FilterDns.sln:5`, `FilterDns/FilterDns.csproj:1-20`
- **What's wrong:** The solution contains only the executable project and no test project. The codebase has complex DNS parser, CIDR, history persistence, IXFR diffing, and transfer orchestration logic with no regression coverage.
- **How it manifests:** Parser regressions, wire-format mistakes, history corruption, and concurrency bugs can ship while `dotnet build` remains green.
- **Fix instructions:** Add a focused test project to the solution. Start with unit tests for `DnsMessageParser`, `IpWhitelist`, `RecordFilter` private-range behavior via public filtering, `ZoneHistoryStorage` round-trips, `RecordComparer`, `ZoneDiffCalculator`, and CAA wire serialization. Add a small integration harness for AXFR/IXFR using in-memory or loopback DNS packets. Keep tests deterministic and not dependent on external DNS.
- **Risk / blast radius:** Adds test infrastructure only; should not change runtime behavior.
- **Depends on:** none
