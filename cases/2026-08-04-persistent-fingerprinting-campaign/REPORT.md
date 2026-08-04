# A Five-Week Fingerprinting Campaign Against Root: Evidence of Consistent Honeypot Detection

Date: August 4, 2026 (analysis conducted). Campaign observed June 25 through August 4, 2026, ongoing.
Type: Honeypot analysis
Frameworks applied: MITRE ATT&CK, Diamond Model, PTES-shaped methodology
Status: Complete for this analysis window; the campaign itself is still active

## Executive Summary

A single source, 195.178.110.227, has been running a persistent SSH credential campaign against a honeypot I operate for at least five and a half weeks, from June 25 through today. It exclusively targets root, with a password list that visibly matures over the campaign, from bare-minimum guesses in June to a structured wordlist with keyboard-walk and leetspeak patterns by late July. On every single successful login across the entire observed window, it runs the exact same fingerprinting command: hardware and OS detection, a GPU check, and an active test for honeypot-like shell behavior. In every session checked, including all 52 sessions on the highest-volume day, it never proceeds past that probe. This case was found through a SIEM dashboard, not a manual log review: a pattern of increasing bytes-per-hour spikes led to noticing the same command signature repeating across separate sessions from one source, which is what prompted the deeper investigation documented here.

## Scope

- Asset: a Cowrie SSH honeypot on a VPS I own and administer. Hostname and IP are intentionally left out here; see the chain-of-custody note below.
- Collection method: passive log review plus SIEM dashboard analysis. No outbound connection was made to any attacker-controlled infrastructure.
- Authorization basis: my own infrastructure, my own honeypot, consistent with the passive-OSINT, no-hacking-back approach this work follows.
- Time window: the full campaign duration observed in available logs, June 25 through August 4, sampled across multiple dates rather than reconstructed session by session for every one of the roughly 90-plus sessions in that window.

## Methodology

1. Discovery via SIEM anomaly, not raw log review. A forensics dashboard showed two increasing bytes-per-hour spikes. Drilling into the underlying sessions showed the same source IP running what looked like identical commands across multiple separate sessions, which is what prompted this investigation rather than a manual sweep of the logs.
2. Campaign duration confirmation. Searched all available daily log files for this source IP to establish the actual span of activity, not just the day it was first noticed.
3. Credential and password-list comparison across sampled dates (June 25, July 2, 10, 19, 28, August 3), to see whether the password list stayed static or changed over time.
4. Full reconstruction of one representative session (August 4) to see the exact fingerprinting command in full, not just that "a command" ran.
5. Verification that the fingerprinting-only behavior wasn't a one-off. Checked command counts across all 52 successful sessions on the highest-volume day (July 28) to confirm the pattern held consistently, not just in the one session initially reviewed.
6. Investigation of the July 28 volume spike specifically, by examining session timestamps rather than assuming the raw count meant a flood.
7. Infrastructure enrichment via WHOIS on the source IP.

### Chain-of-custody note

The VPS's real hostname and IP are intentionally left out of this report, for the same reason as the first case in this repo: the discipline only means something if it's applied consistently, not selectively. Attacker-side infrastructure is included in full, since sharing that is standard, expected practice in threat intel.

## Findings

### Finding 1: A single actor sustained a five-week campaign, confirmed through identical tooling, not IP reputation alone

Confidence: confirmed.

Evidence: the exact same fingerprinting command, byte for byte, appears in successful sessions from 195.178.110.227 on June 25, July 10, July 28, and August 4, spanning the full available log retention.

Analysis: attribution here doesn't rest on the IP alone, which could in principle change hands or be reassigned. It rests on the actor running unmodified tooling across five-plus weeks, a stronger and more durable basis for saying "this is one campaign" than IP reputation by itself.

### Finding 2: Exclusive targeting of root, with a maturing password list

Confidence: confirmed.
MITRE ATT&CK mapping: T1110.001, Password Guessing.

Evidence: across every sampled date, only the root username was ever attempted. Password sophistication changed visibly over time.

| Date | Sessions | Unique passwords | Sample |
|---|---|---|---|
| Jun 25 | 3 | 2 | 111111, 123 |
| Jul 10 | 15 | 14 | 12345678, Password1, letmein |
| Jul 19 | 11 | 10 | !root, P@ssw0rd |
| Jul 28 | 54 | ~37 | 1q2w3e4r, 1qaz@WSX, r00t, root!@# |
| Aug 3 | 5 | 4 | !root, 111111, 123123, 123321 |

Analysis: this isn't a static script run unchanged. The password list itself grew more structured and sophisticated across the campaign, keyboard-walk patterns and leetspeak substitutions appearing only in the later dates, indicating active maintenance of the tooling over the five-week window.

### Finding 3: A comprehensive, unvarying fingerprinting probe on every successful login

Confidence: confirmed.
MITRE ATT&CK mapping: T1082 (System Information Discovery), T1033 (System Owner/User Discovery), T1497.001 (Virtualization/Sandbox Evasion: System Checks).

Evidence: reconstructed in full from an August 4 session. A single command, always run first and only, that:

- Detects OS and kernel via uname, with fallbacks to /bin/uname, /usr/bin/uname, busybox uname, /proc/version, and /etc/os-release.
- Detects CPU architecture via uname -m with fallbacks, plus /proc/cpuinfo flag matching for x86_64, aarch64, and armv7l.
- Gathers uptime, CPU core count, and CPU model, including a check against /proc/device-tree/model specifically for ARM single-board devices.
- Checks for a GPU via lspci grep for VGA and NVIDIA entries.
- Pulls login history with last.
- Runs a shell-behavior test: executes a deliberately nonexistent command to inspect the resulting error text, then writes, makes executable, and runs a small test script through a chain of shell fallbacks (bash, /bin/bash, /usr/bin/bash, busybox sh, sh) to confirm real script execution behaves as expected.

Analysis: the GPU check is notable on its own. General credential-stuffing bots targeting Linux servers don't typically care about graphics hardware. It points toward interest in compute-hijacking value, cryptomining or unauthorized workload placement, rather than a generic botnet recruitment script. The shell-behavior test is active sandbox and honeypot detection, checking whether the environment behaves like a real system before committing to anything further.

### Finding 4: The campaign never proceeds past the fingerprinting stage

Confidence: confirmed, not inferred from a single session.

Evidence: all 52 successful sessions on July 28, the highest-volume day observed, ran exactly 9 commands each, no more, no fewer, matching the fingerprinting probe exactly. In the August 4 session, several of the OS-detection fallback checks came back as failed against the honeypot's shell emulation, and the session closed immediately afterward with no further activity.

Analysis: checking one session and assuming the pattern generalizes would have been an inference, not a finding. Verifying it across all 52 sessions on the busiest day is what makes this a confirmed behavior rather than a guess. This actor consistently declines to proceed once it has fingerprinted the environment, which given the failed detection checks in the reconstructed session, may reflect a limit in how far the honeypot's fake filesystem can convincingly hold up under close inspection.

### Finding 5: The July 28 "spike" was two scheduled batches, not a flood

Confidence: confirmed.

Evidence: session timestamps on July 28 cluster into two distinct windows, 08:55 to 09:28 and 16:28 to 17:26, with sessions spaced roughly 90 seconds apart within each window.

Analysis: the raw session count alone, 54 versus a baseline of single digits on quieter days, would suggest an anomalous flood. Looking at the actual timing shows a steady, evenly-paced operating rhythm consistent with a scheduled job running roughly twice a day, not a burst of unusual intensity. Days with fewer sessions are likely partial or single batches on whatever schedule drives this, not a fundamentally different behavior.

## Evidence / Artifacts

- One fully reconstructed session (August 4): full fingerprinting probe, reconstructed in complete detail.
- Password lists extracted per sampled date (June 25, July 2, 10, 19, 28, August 3).
- Command counts for all 52 successful sessions on July 28, confirming the fingerprinting-only pattern held across the full day.
- WHOIS record for 195.178.110.227: TECHOFF SRV LIMITED, registration details split between Andorra and the United Kingdom depending on field, consistent with the low-scrutiny hosting pattern also seen in this repo's first case.

## Recommendations / Next Steps

- For any real production system: disable root SSH login entirely. This specific campaign only ever targets root, so this single control fully defeats it regardless of password strength.
- Detection engineering angle: the fingerprinting probe's exact structure, the GPU check combined with the deliberate error-format test and the multi-shell script-execution check, is a durable, specific behavioral signature. A detection rule matching on that command pattern would catch this actor's tooling regardless of which IP it originates from next, which matters given the infrastructure will likely rotate the way it did in the earlier case in this repo.
- The roughly 90-second interval between login attempts within a batch is itself a detectable rhythm, worth a rule flagging repeated authentication attempts from one source at regular short intervals, independent of whether the specific commands are known yet.
- The hosting provider, TECHOFF SRV LIMITED, has a standard abuse-reporting channel. A passive report citing this campaign's duration and pattern is a reasonable next step.

## Lessons Learned

- Campaign attribution over time needs tooling consistency, not just IP reputation. Five weeks of identical command signatures is a much stronger basis for "this is one actor" than the IP address alone would have been.
- A negative result, "it never escalates," is a real finding when it's actually verified, not assumed. Checking all 52 sessions on the busiest day instead of generalizing from one session is what turned "seems like it always stops here" into a confirmed, defensible claim.
- The SIEM dashboard is what actually surfaced this, not a manual review. Watching an aggregate signal like bytes-per-hour and letting an anomaly there lead to the specific sessions is a materially different, and more realistic, discovery process than starting from raw logs.
