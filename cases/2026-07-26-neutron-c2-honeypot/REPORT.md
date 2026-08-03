# Neutron C2: A Two-Stage Linux Botnet Dropper Campaign Against an SSH Honeypot

Date: August 3, 2026 (analysis conducted). Incident window: July 24 to 27, 2026, with the main activity on July 26.
Type: Honeypot analysis
Frameworks applied: MITRE ATT&CK, Diamond Model, PTES-shaped methodology
Status: Complete

## Executive Summary

A four-day window around July 25 and 26, 2026 showed three to four times the normal traffic on a Cowrie SSH honeypot I run. At first it looked like one attacker was behind the spike. Session-level correlation showed otherwise: two unrelated campaigns were overlapping in the same window. One was a high-volume credential-spraying scanner (8.218.231.192, 5,521 sessions in a single day) that never got past login attempts. The other was a much smaller but fully successful actor (91.92.40.237, about 1,420 sessions) running a complete attack chain that calls itself "Neutron C2" in its own source code. That chain included reconnaissance, an attempt to kill competing processes, and two dropper scripts of increasing sophistication. The second used CPU architecture fingerprinting, hex-obfuscated construction, and a five-method download fallback down to a raw /dev/tcp socket. No real malware ever ran: Cowrie's shell emulation doesn't execute arbitrary scripts, so the honeypot captured the attacker's full intent and tooling without any real risk.

## Scope

- Asset: a Cowrie SSH honeypot on a VPS I own and administer. Hostname and IP are intentionally left out here; see the chain-of-custody note below.
- Collection method: passive log review only. No outbound connection was made to any attacker-controlled infrastructure. The one payload analyzed, deploy.sh, had already been captured automatically by Cowrie at the time of the original session, so there was no need to contact the C2 directly.
- Authorization basis: my own infrastructure, my own honeypot, consistent with the passive-OSINT, no-hacking-back approach this work follows.
- Out of scope: both dropper scripts reference architecture-specific payload binaries (real_x86_64, real_mips, and so on). Cowrie never fetched them, and they weren't retrieved separately. Doing that would mean live contact with the C2, which wasn't necessary for this analysis.

## Methodology

1. Volume baseline comparison. Event-type counts for four consecutive days (July 24 through 27) established what normal traffic looks like before treating anything as anomalous.
2. Anomaly identification. July 25 and 26 stood out: login success rate jumped from a 22 to 29 percent baseline to 71 percent, and commands per session jumped roughly 17x, from about 0.35 to about 6.1. That's a change in shape, not just more noise.
3. Actor attribution through session correlation, not aggregate IP counts. The initial assumption was that the single highest-volume source IP, 8.218.231.192, was behind the spike. Correlating session IDs between connection events and the sessions that actually ran the dropper commands showed zero overlap. The loud IP and the actor running the real attack chain were two separate things happening at the same time. Reporting the noisy scanner as "the attacker" would have simply been wrong.
4. Full session reconstruction. Rather than trust aggregated command counts, one complete session (91.92.40.237, session ID 68d77f68ac12) was reconstructed in full chronological order, every event timestamped, to see the actual sequence instead of inferring it from totals.
5. Static analysis of the captured artifact. deploy.sh had already been captured by Cowrie at the time of the incident. It was identified with the file command and read as plain text, never executed, in keeping with a static-analysis-first approach to anything the honeypot captures.
6. Infrastructure enrichment. Basic WHOIS lookups on the actor's IP and the C2 host established hosting and registration context.

### Chain-of-custody note

The VPS's real hostname and IP are intentionally left out of this report, even though including them would make some of the log excerpts easier to follow. Chain-of-custody discipline only means something if it's a habit, not something applied selectively. Attacker-side infrastructure (their IPs, file hashes, C2 domains) is included in full, since sharing that kind of detail is standard, expected practice in threat intel. The redaction applies to my own infrastructure, not the adversary's.

## Findings

### Finding 1: Two unrelated campaigns overlapped in the same window

Confidence: confirmed, through session-ID correlation, not inference.

Evidence: 8.218.231.192 ran 5,521 unique sessions on July 26 alone, with zero overlap with the 1,423 sessions that ran the deploy.sh command. 91.92.40.237 accounted for 1,421 of those 1,423 sessions. Two single-session outliers came from 91.92.40.18 and 176.65.148.93, possibly the same or shared tooling.

Analysis: most of the volume spike was generic credential-spraying noise. The actual successful, multi-stage campaign was much smaller in volume but far more significant, and reporting on aggregate top-IP stats alone would have pointed at the wrong actor entirely.

### Finding 2: A distinctive, reused credential set

Confidence: confirmed.
MITRE ATT&CK mapping: T1110, Brute Force.

Evidence: the top successful credentials across July 25 and 26 were root with a blank password (1,641 times), root:3245gs5662d34 (807 times), postgres:postgres (266), admin:admin (103), and admin:3245gs5662d34 (48). The same unusual password string, 3245gs5662d34, also showed up under the postgres account.

Analysis: a password string that specific, reused across multiple usernames, points to a curated credential list rather than a generic public wordlist. That's a distinctive, checkable detail, not just "they used common passwords."

### Finding 3: Full attack chain, reconstructed session (68d77f68ac12, from 91.92.40.237)

Confidence: confirmed.
MITRE ATT&CK mapping: T1110 for initial access, System Information Discovery for the writability recon, T1057 Process Discovery, T1105 Ingress Tool Transfer, T1059.004 Unix Shell, T1027 Obfuscated Files or Information, and T1036 Masquerading.

Evidence, all times UTC, July 26, 2026:

- 00:00:39.098, connect.
- 00:00:40.615, login success, root with a blank password.
- 00:00:43 to 00:00:48, writability checks across /tmp, /var/tmp, /dev/shm, /var/run, /var, and /tmp/.cache.
- 00:00:49.651, a loop scanning every /proc/[pid]/maps and killing anything not linked to standard system libraries. This is competitor-elimination behavior, and it partially failed: Cowrie's shell parser fragmented the multi-line control structure.
- 00:00:49.674 to 00:00:49.687, deploy.sh fetched through two fallback methods. sha256: 0d7fd4d7f637e1f8c492fd41a675b03cce3fa1f7601bf4e9fc8703cce1da259f.
- 00:01:09.640, echo DEPLOY_CHECK, a verification or heartbeat string.
- 00:01:11 to 00:01:13, a second script, update.sh, built through roughly 20 hex-encoded echo commands appended to a file. A simple way to dodge plaintext pattern matching.
- 00:01:13.377, chmod 777 update.sh.
- 00:01:13.878, ./update.sh executed, and failed. Cowrie doesn't execute attacker-authored scripts; more on that in Finding 5.
- 00:01:28.879, echo SCRIPT_OK. The bot echoes this regardless of the actual failure above, so this isn't a real conditional check, more a scripted assumption of success.
- 00:01:30.879 to 00:01:30.884, six file_download events. On inspection these turned out to be re-reads of files already created earlier in the session (a 9-byte "WRITABLE" test file and the 1,945-byte update.sh script itself), not new external binaries.
- 00:01:30.896, session closed. Total duration: about 51 seconds.

Analysis: a complete, automated, multi-stage playbook that ran in under a minute, with a built-in verification pattern and reasonably graceful handling of its own failure.

### Finding 4: Escalating dropper sophistication within a single campaign

Confidence: confirmed.
MITRE ATT&CK mapping: T1105 Ingress Tool Transfer, T1027 Obfuscation.

Evidence: deploy.sh, 17 lines, tries five hardcoded architectures (mips, mipsel, arm, arm64, x86_64) in sequence against http://91.199.133.133:8080/. update.sh, 1,945 bytes and hex-obfuscated, instead fingerprints the CPU directly from /proc/cpuinfo, normalizes to a single target architecture, and falls back through five separate delivery methods: wget, curl, busybox wget, tftp, and finally a raw /dev/tcp bash built-in used to hand-construct an HTTP GET request when nothing else is available.

Analysis: the same operator is running at least two dropper variants of meaningfully different sophistication in a single session. That points to active tooling development, not a static script reused unchanged.

### Finding 5: Honeypot fidelity held against this campaign, with one specific boundary

Confidence: confirmed.

Evidence: the session ran to a full, natural close (51 seconds, clean disconnect) rather than an abrupt one, which is the signal you'd expect from a bot that noticed something was off.

Analysis: the fake filesystem on this honeypot was convincing enough that it didn't trip whatever detection logic this particular bot has. The one place things broke, ./update.sh not executing, isn't a fidelity gap. It's a structural property of Cowrie as a command-and-response emulator rather than a real shell. Improving the fake filesystem further (more realistic /proc/cpuinfo content, deeper log history, more populated directories) is a safe, incremental project. Getting a bot's own script to actually execute would require a fundamentally different setup: a real, disposable, carefully isolated VM, not a configuration tweak.

## Evidence / Artifacts

- cowrie.json.2026-07-24 through cowrie.json.2026-07-27: daily rotated Cowrie JSON logs, retained on the VPS.
- Session 68d77f68ac12: full event sequence, timestamps as above.
- deploy.sh: captured artifact, sha256 0d7fd4d7f637e1f8c492fd41a675b03cce3fa1f7601bf4e9fc8703cce1da259f, stored in Cowrie's downloads directory.
- WHOIS records for 91.92.40.237 (TechTies Inc., registered in Seychelles) and 91.199.133.133 (AlexHost SRL, Moldova). Both are budget, low-KYC hosting providers, a common pattern for disposable C2 infrastructure.
- Broader context: this honeypot's download archive holds 2,013 unique captured artifacts, about 1.1GB, across roughly six months of continuous operation. This incident is one specific, bounded slice of that archive, not the whole of it.

## Recommendations / Next Steps

- For any real production system: turn off password authentication on internet-facing SSH entirely, or at minimum get rid of blank and default credentials. The weak-credential pattern here, root with a blank password plus a handful of common weak passwords, is exactly what keeps this class of attack viable at scale.
- Egress filtering on production servers would have stopped this chain at the wget-to-port-8080 step. Outbound connections to non-standard ports from a server that has no reason to make them are cheap and practical to block.
- A detection rule built around the behavioral sequence (writability probes across several temp directories, followed by a /proc/[pid] sweep, followed by a multi-architecture wget attempt) will hold up longer than blocking these specific IPs. That infrastructure will rotate. The sequence is closer to the actor's actual tradecraft.
- The C2 hosting provider, AlexHost SRL, has a real abuse-reporting channel. A passive abuse report citing the captured deploy.sh and its hardcoded C2 endpoint is a reasonable next step.

## Lessons Learned

- Aggregate stats can mislead. Session-level correlation is what actually proves attribution. The highest-volume IP in this window wasn't the actor running the real attack chain, and treating volume as a stand-in for significance would have been a factual error in this report.
- A "failed" command in a honeypot log isn't automatically something to leave out. Understanding why ./update.sh failed turned into one of the more specific, defensible findings in this case, not a footnote.
- Real operators iterate mid-campaign. Seeing two dropper variants of different sophistication in the same session wasn't visible in the initial aggregate command counts. It only showed up once the full session was reconstructed in order.
