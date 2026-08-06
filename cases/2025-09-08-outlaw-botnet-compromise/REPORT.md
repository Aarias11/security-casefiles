# Outlaw (Dota) Botnet Compromise of a Production VPS

Date: September 2025 (incident), August 2026 (retrospective analysis)
Type: Incident response / Malware analysis / Threat intelligence
Frameworks applied: MITRE ATT&CK, Diamond Model of Intrusion Analysis
Status: Complete

## Executive Summary

A VPS I own and administer was compromised in September 2025 by the botnet tracked publicly as Outlaw, also referred to as Dota. The host was used to conduct SSH brute-force attacks against at least 140 third-party systems until my hosting provider forwarded an abuse report. The root cause was a cloud-init configuration drop-in that silently re-enabled SSH password authentication despite my primary SSH configuration explicitly disabling it, a failure mode that is invisible when inspecting the configuration file itself.

The intrusion deployed two components running concurrently, a command-and-control beacon and a mass SSH scanner, backed by redundant cron persistence with fallback paths and an attacker-planted SSH key. Resource consumption from the mining component took a co-hosted application offline. Total dwell time before detection was approximately four days, and detection came entirely from an external party rather than from any control of mine.

Retrospective analysis eleven months later established that the same actor, using byte-identical tooling and an unrotated SSH key, accounted for 70,626 sessions against my replacement infrastructure's honeypot between February and August 2026, roughly 27% of all sessions in which commands were executed. That confirms the original compromise as opportunistic mass-scanning rather than targeted intrusion, a conclusion that was not available during the incident and became possible only because collection continued afterward.

## Scope

### In scope

- The September 2025 compromise of a VPS I own, from initial access through remediation and provider notification.
- Analysis of the one malware component recovered before the host was destroyed: a Perl IRC bot.
- Correlation of that incident against six months of subsequent honeypot telemetry collected on the replacement host, to determine whether the same actor remained active.
- Attribution to a publicly documented threat cluster, limited to comparison of observed TTPs against published research.

### Out of scope

- Any interaction with attacker infrastructure. The command-and-control addresses identified during analysis were never probed, scanned, or connected to. All C2 detail here was derived from static analysis of a recovered script and from passive observation of the compromised host's own outbound connections.
- Any contact with the victim hosts named in the provider abuse report. Roughly 140 third-party addresses were listed as targets. None were scanned, contacted, or investigated.
- Reverse engineering of the mining component. The binary was destroyed with the host before a sample was preserved.
- Attribution beyond TTP matching. No claim is made about the identity, nationality, or affiliation of any operator.

### Chain-of-custody note on redaction

My own infrastructure is not identified in this report. The compromised VPS's hostname and IP address, my administrative source addresses, the provider's name, and the abuse ticket reference are all intentionally omitted, even where including them would make some log excerpts easier to follow. This is the same discipline applied in my other published cases: redaction covers my infrastructure, not the adversary's. Attacker-side detail, C2 addresses, source addresses, file paths, process names, key material comments, and command sequences, is included in full, since sharing that is standard and expected practice in threat intelligence.

This case adds one category my previous cases did not have. The provider's abuse report named approximately 140 third-party victim hosts. Those addresses are also omitted, for a different reason: they belong to uninvolved parties who were attacked, and publishing a list of systems that were recently brute-forced would be republishing a target list. Where victim addresses appear in log excerpts below they are replaced with generic labels, which preserves the analytical point without exposing the hosts.

### Evidence limitations

These constraints materially limit what this report can prove, and are stated up front rather than buried:

- The original host was destroyed before forensic imaging. Remediation prioritised stopping active outbound attacks over evidence preservation, and the VPS was reinstalled roughly four days after detection. No disk image or memory capture exists.
- No memory forensics. The malicious processes were observed live and their output recorded, but no memory dump was taken.
- The miner binary was not preserved. Its size, location, behaviour and resource consumption were documented; the file itself is gone.
- Honeypot logs from the compromised host did not survive the rebuild. Honeypot data referenced here comes from the replacement host, including the September 2025 records used in Finding 5: the replacement was online and collecting within days of the rebuild, so its earliest data is contemporaneous with the incident's aftermath rather than surviving from the compromised machine.
- The moment of initial access is not established. Authentication logs were reviewed only back to roughly three days before the earliest confirmed attacker activity, and the original `authorized_keys` file was not retained. The initial access chain is partly inferred; the reasoning and its limits are set out in Finding 1.
- Portions of the timeline are reconstructed from contemporaneous notes taken during live response rather than from primary log artifacts. Where a claim rests on notes, this report says so.

## Methodology

This investigation happened in two distinct phases, eleven months apart, under very different constraints. They are documented separately because collapsing them into a single narrative would misrepresent how the conclusions were reached. Phase 1 was live incident response under time pressure while the host was actively attacking third parties. Phase 2 was retrospective analysis with surviving artifacts, a full honeypot dataset, and no urgency.

### Phase 1: Live incident response (September 2025)

1. **Initial signal, not recognised as compromise.** Host monitoring raised alerts on unusual activity. Initial response was to enrich source addresses via WHOIS and public reputation lookups. The activity was interpreted as inbound scanning noise, which is the normal background condition for an internet-facing host. No compromise was suspected. In hindsight the malicious crontab had been installed roughly four hours earlier that same morning.

2. **External escalation.** Four days later the hosting provider forwarded a third-party abuse report stating the VPS was the *source* of SSH brute-force traffic against approximately 140 hosts on another provider's network, with timestamped log excerpts. This reframed the problem: the concern was no longer inbound attacks, but outbound attacks originating from my host.

3. **Live triage of outbound connections.** Rather than starting from filesystem searches, the first diagnostic was enumerating active connections (`lsof -i -nP | grep ESTABLISHED`). An abuse report about outbound traffic is best confirmed or refuted by looking at what the host is actually connected to. The output was decisive and revealed two distinct malicious processes running simultaneously (Finding 2).

4. **First containment attempt, and the failure that produced a finding.** The malicious process was killed and the binary at `/tmp/.kswapd00` and `/var/tmp/.kswapd00` deleted. After a reboot the process returned under a new PID. That failure was more informative than success would have been: it proved persistence existed somewhere not yet identified, and redirected the investigation from cleanup to persistence hunting.

5. **Out-of-band analysis via rescue mode.** The host was rebooted into the provider's rescue environment, which boots a separate clean operating system and mounts the original disk as secondary storage. This was the single most important methodological decision in Phase 1. It allowed the filesystem to be examined with the malware inert, rather than analysing a live system whose own binaries could not be trusted.

6. **Systematic persistence hunt against the mounted disk.** Standard Linux persistence locations were checked in order of likelihood: systemd unit files (clean), then cron. The user crontab contained the persistence mechanism, timestamped the morning of the compromise, with redundant entries and `@reboot` triggers. This directly explained the failed containment in step 4.

7. **Artifact discovery.** Following the paths referenced in the crontab led to a hidden directory structure (`.configrc7/` containing `a/` and `b/` subdirectories) and a second staging path under `/tmp` using a directory name mimicking a legitimate X11 socket directory. Inspection of `~/.ssh/authorized_keys` revealed an attacker-planted public key.

8. **Remediation and root cause.** SSH keys were rotated, password authentication and root login disabled, and persistence artifacts removed. Investigating *why* password authentication had been available despite being explicitly disabled identified the root cause (Finding 1).

9. **Host rebuild.** Given confirmed root-level compromise and no certainty all persistence had been identified, the host was fully reinstalled rather than cleaned. This decision prioritised stopping the outbound attacks over preserving forensic evidence, and is the direct cause of the evidence limitations declared above.

### Phase 2: Retrospective analysis (August 2026)

10. **Artifact recovery.** One component, a Perl IRC bot, had been copied off the compromised host before rebuild and retained on a separate analysis workstation. Shell history on that workstation preserved the exact transfer, establishing chain of custody from the destroyed host to the surviving copy.

11. **Static analysis.** The script was read in full and its capabilities catalogued. Its C2 address was stored as an obfuscated hexadecimal value rather than plaintext; decoding it yielded `179.43.139.83`.

12. **Independent corroboration of the C2 address.** That decoded address was compared against IOC notes written during Phase 1, eleven months earlier, using an entirely different method (regular expression extraction over the decoded payload). Both produced the same address. Two independent derivations agreeing is stronger than either alone.

13. **Re-examination of Phase 1 conclusions.** The contemporaneous response record was reviewed against surviving artifacts. Three conclusions did not survive scrutiny and are corrected below.

14. **Longitudinal correlation.** The attacker's planted SSH key carried a distinctive comment string. That string was searched across six months of honeypot logs from the replacement host (approximately 1.4 million sessions), establishing whether the same actor remained active after the rebuild. Result in Finding 5.

15. **External validation of attribution.** Only after internal evidence was assembled were observed TTPs compared against published threat intelligence, deliberately in that order, so public research confirmed independently derived findings rather than shaping them.

### Corrections to Phase 1 analysis

Three conclusions reached during live response were later overturned by evidence. They are documented rather than silently removed, because the corrections are part of the methodology.

**Correction 1: Key ownership was misattributed.** Phase 1 concluded that logins over a four-day window used "the attacker's ED25519 key," and that I had unknowingly been authenticating with it. This is cryptographically impossible. Public key authentication requires possession of the corresponding private key; authenticating successfully against a public key proves ownership of it. The key in question was my own.

**Correction 2: A benign source was labelled hostile.** Building on Correction 1, Phase 1 concluded the attacker had been "proxying through the ISP's range" because sessions appeared from my own home address. That address is confirmed mine and appears throughout current infrastructure logs as normal administrative access. The conclusion was inference layered on an earlier error, not evidence.

**Correction 3: The stated compromise window contradicts a primary artifact.** Phase 1 identified initial compromise as occurring in a late-afternoon window based on successful password authentications. The malicious crontab recovered from the same host is timestamped that morning, roughly nine hours earlier. A session beginning in the afternoon cannot have created a file that morning. The password authentications in that window are more consistent with my own investigation, which had begun by midday.

The methodological lesson from all three: the first two originated from assuming attribution rather than deriving it, and the third from anchoring on one log source while a contradicting artifact sat in the same evidence set. All three were caught by cross-referencing independent sources, not by re-reading the same data more carefully.

## Findings

### Finding 1: SSH password authentication silently re-enabled by a cloud-init drop-in

- Severity / Confidence: Critical / Confirmed
- MITRE ATT&CK: T1078 (Valid Accounts)

**Evidence.** The host's primary SSH configuration at `/etc/ssh/sshd_config` contained `PasswordAuthentication no`. A separate drop-in created by cloud-init at `/etc/ssh/sshd_config.d/50-cloud-init.conf` contained `PasswordAuthentication yes`. Authentication logs recorded successful password-based SSH logins during the incident window, which the primary configuration should have made impossible.

**Analysis.** On Ubuntu cloud images, `/etc/ssh/sshd_config` begins with an `Include /etc/ssh/sshd_config.d/*.conf` directive. OpenSSH resolves most keywords using the **first** value obtained, not the last. Because the include sits at the top of the file, any setting in a drop-in is parsed before the corresponding setting in the main configuration and therefore wins. This inverts the precedence most operators expect, where a later or more specific entry overrides an earlier one.

The failure mode is silent. `sshd` produces no warning, the main configuration still visibly reads `PasswordAuthentication no`, and an operator inspecting only that file has no indication the setting is inert. Verifying effective configuration requires `sshd -T`, which reports runtime values actually in force rather than the contents of any single file.

This is the root cause enabling credential-based access. Worth stating plainly: the intended hardening was correct and had been deliberately applied. A platform default silently reversed it.

**Initial access chain: established versus inferred.** The precise moment of initial access is not present in retained evidence. The distinction is recorded rather than smoothed over.

*Established by direct evidence:*
- Password authentication was available despite the primary configuration disabling it.
- By the morning of the compromise the attacker was authenticating successfully using an RSA public key from `91.132.138.238`, meaning key-based access already existed.
- An attacker-controlled key bearing the comment `mdrfckr` was present in `~/.ssh/authorized_keys`.
- The persistence crontab was written shortly afterward, after key-based access was already in use.

*Inferred from directly observed campaign behaviour:* the key was most likely planted immediately following a successful password authentication. This is not speculation about generic attacker behaviour; it is the specific fixed playbook of this campaign, observed 70,626 times in my own honeypot telemetry (Finding 5):

```
1. authenticate with brute-forced credentials
2. cd ~; chattr -ia .ssh; lockr -ia .ssh
3. rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...mdrfckr" >> .ssh/authorized_keys
4. chmod -R go= ~/.ssh
5. all subsequent access uses the planted key
```

The default `ubuntu` username on Ubuntu cloud images means only one half of the credential pair required guessing.

*Not established:* the timestamp of the original successful password authentication; whether the account password was weak, reused, or previously exposed; and whether password brute force was the vector at all as opposed to some other means of writing to `authorized_keys`. It is by far the most probable explanation given the confirmed misconfiguration and the campaign's known behaviour, but no log entry proves it for this host specifically.

**Unresolved inconsistency worth recording.** The campaign playbook deletes the entire `.ssh` directory before writing its own key, which should leave `authorized_keys` containing the attacker key alone. However, I continued authenticating with my own key during the days following, which requires that my key was also present. Either a variant that appends without wiping was used, or my key was added to the host after the attacker's key was planted, which would place initial compromise earlier than the date established here. The original file was not retained, so this cannot be resolved.

### Finding 2: Two-component malware architecture running concurrently

- Severity / Confidence: High / Confirmed
- MITRE ATT&CK: T1071.001 (Application Layer Protocol: Web Protocols), T1110.001 (Brute Force: Password Guessing), T1036.005 (Masquerading: Match Legitimate Name or Location)

**Evidence.** Live enumeration of established connections recorded two distinct processes owned by the unprivileged service account, running simultaneously:

```
kauditd0    ->  179.43.139.85:80    (single persistent connection)
kthreadad   ->  [several hundred outbound connections, port 22 and variants]
```

`kthreadad` held several hundred concurrent outbound connections, predominantly to port 22 but also 2222, 2200, 2022, 8022, 10022, 22222 and other non-standard SSH ports, against globally distributed addresses. A later observation recorded it consuming 165% CPU and roughly 2.4 GB resident memory on a host with 2 vCPUs and 3.7 GB RAM.

**Analysis.** This is a division of labour rather than a single monolithic implant. `kauditd0` maintains one persistent outbound connection to a single remote host on port 80, consistent with C2 beaconing over a port chosen to blend with ordinary web traffic. `kthreadad` performs propagation, conducting mass SSH brute-force against external targets.

Both names are masquerades of legitimate Linux kernel threads: `kauditd` (kernel audit daemon) and `kthreadd` (kernel thread daemon). Neither is correct, but both are close enough to pass a cursory scan of `ps` output, and both would be mentally filtered by an administrator expecting bracketed kernel threads.

The resource consumption is independently significant. At 165% of 200% available CPU and roughly two thirds of available memory, the host had insufficient capacity for its legitimate workload (Finding 4).

### Finding 3: Redundant multi-layer persistence with fallback paths

- Severity / Confidence: High / Confirmed
- MITRE ATT&CK: T1053.003 (Scheduled Task/Job: Cron), T1098.004 (Account Manipulation: SSH Authorized Keys), T1036.005 (Masquerading)

**Evidence.** A user crontab recovered from the mounted disk contained:

```
*/30 * * * * /tmp/.kswapd00 || ~/.configrc7/a/kswapd00 > /dev/null 2>&1
5 6 */2 * 0  ~/.configrc7/a/upd>/dev/null 2>&1
@reboot      ~/.configrc7/a/upd>/dev/null 2>&1
5 8 * * 0    ~/.configrc7/b/sync>/dev/null 2>&1
@reboot      ~/.configrc7/b/sync>/dev/null 2>&1
0 0 */3 * *  /tmp/.X2t-unix/.rsync/c/aptitu[...]
```

Additional artifacts: a hidden directory `~/.configrc7/` containing `a/` and `b/` subdirectories; a staging directory at `/tmp/.X2t-unix/`; and an attacker-controlled public key appended to `~/.ssh/authorized_keys` bearing the comment `mdrfckr`.

**Evidence of function.** An initial containment attempt that killed the running process and deleted `/tmp/.kswapd00` was followed by the process returning under a new PID after reboot. Separately, the recovered `.kswapd00` binary carried a modification timestamp matching the recorded system reboot time rather than the original infection date.

**Analysis.** This is deliberately engineered redundancy, not incidental duplication.

The primary entry uses a shell `||` fallback: if `/tmp/.kswapd00` fails to execute, a second copy in a hidden home directory runs instead. Deleting the obvious `/tmp` artifact therefore does not remove the implant, it activates the backup path. This is precisely what defeated the first containment attempt.

Three components (`kswapd00`, `upd`, `sync`) are scheduled independently, two with `@reboot` triggers, so a reboot re-establishes the infection rather than clearing it. The binary timestamp matching reboot time is direct evidence this worked as designed: the file's date records the moment my own reboot triggered the malware to rewrite itself.

Naming reinforces concealment. `.configrc7` mimics a legitimate dotfile. `.X2t-unix` mimics `/tmp/.X11-unix`, a real X11 socket directory. `aptitu[...]` echoes the Debian package tool `aptitude`. Each is plausible enough to survive a quick visual scan.

The planted SSH key is a separate persistence layer entirely, independent of cron, and would have survived removal of every scheduled task.

### Finding 4: Confirmed third-party impact and a deliberately rate-limited attack pattern

- Severity / Confidence: High / Confirmed
- MITRE ATT&CK: T1110.001 (Brute Force: Password Guessing)

**Evidence.** The hosting provider forwarded a third-party abuse report identifying my host as the source of SSH brute-force traffic against approximately 140 addresses within a single reporting organisation's network, with timestamped log excerpts. Victim addresses are replaced below with generic labels, per the chain-of-custody note above. A representative sample:

```
08:16:20  user: enable    target: [victim host A]   source: [my VPS]
08:16:18  user: enable    target: [victim host B]   source: [my VPS]
08:15:20  user: deposito  target: [victim host A]   source: [my VPS]
08:15:08  user: deposito  target: [victim host B]   source: [my VPS]
08:14:30  user: hadoop    target: [victim host A]   source: [my VPS]
08:14:18  user: hadoop    target: [victim host B]   source: [my VPS]
```

Observed attack windows across the reported day: 05:34 to 05:38, 07:01 to 07:05, 08:03 to 08:17, 08:40 to 08:50.

Usernames attempted included `root`, `jenkins`, `hadoop`, `geoserver`, `sqldba`, `mail`, `core`, `enable`, `test1`, `deposito`, `black`, `pal`, `mos`, `acer`, `agouser`, `anonymous`, `user1`.

**Analysis.** The timing pattern is the significant finding. A single username is attempted against multiple targets within seconds, then the next username follows exactly sixty seconds later. The per-target attempt rate is therefore roughly one per minute, below the thresholds most rate-limiting and intrusion-prevention tooling uses to identify brute-force activity.

This is not an unsophisticated flood. It is a deliberately slow, methodical dictionary walk executed against a very large target set in parallel. Any single victim observes what looks like negligible background noise; the activity becomes visible only in aggregate, which is why detection came from a provider correlating across its whole network rather than from any individual target.

The scope is larger than the report implies. The ~140 addresses are explicitly described as hosts "in our Network," meaning one organisation's visibility only. My host's own connection table showed several hundred concurrent sessions to globally distributed addresses, so 140 is a floor rather than a total.

The username list is oriented toward servers and infrastructure rather than consumer devices: `jenkins` (CI), `hadoop` (data platform), `geoserver` (GIS), `sqldba` (database administration), `enable` (network equipment).

**Impact on my own workload.** An application backend hosted on the same VPS became unresponsive during this period. Given the resource consumption in Finding 2, resource starvation is a sufficient explanation and no other cause was identified.

**Detection gap.** The outbound attack traffic in the report occurred a day before notification reached me, roughly 36 hours later. The compromise itself had been established for days prior, giving a total dwell time before detection of approximately four days.

### Finding 5: The same threat actor continued targeting replacement infrastructure for at least six months

- Severity / Confidence: Informational (intelligence finding) / Confirmed
- MITRE ATT&CK: T1098.004 (Account Manipulation: SSH Authorized Keys)

**Evidence.** The public key planted in `~/.ssh/authorized_keys` during the compromise carried the comment string `mdrfckr`.

The compromised host was destroyed and rebuilt. A Cowrie SSH honeypot was deployed on the replacement infrastructure. Analysis of its logs covering February to August 2026 identified approximately 261,631 sessions in which at least one command was executed. Of those, **70,626 sessions** executed a sequence beginning `cd ~; chattr -ia .ssh; lockr -ia .ssh`, followed by a command writing an `ssh-rsa` public key to `authorized_keys` terminating in the identical comment string `mdrfckr`.

The key material and command sequence observed in the honeypot are byte-identical to the key recovered from the compromised host eleven months earlier.

**Artifact-level confirmation.** The command-string match above is corroborated by a stronger form of evidence. Cowrie captures the `authorized_keys` file at the moment the attacker writes it, storing it by content hash. The captured artifact is a 389-byte OpenSSH RSA public key with SHA256 `a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2`, whose contents terminate in the comment `mdrfckr`. Hash verified directly against the stored file.

The same SHA256 appears in honeypot logs retained from September 2025, and the file remained in active delivery as of 5 August 2026, observed in a session originating from `112.216.108.62` (LG DACOM, South Korea). Because Cowrie deduplicates captures by hash, the on-disk copy is dated to its first observation on the current host in February 2026.

This establishes an eleven-month artifact-level match: the same 389 bytes, unchanged, spanning a full host rebuild. That is materially stronger than a command-string match, which could in principle be reproduced by a different actor copying a published playbook. An identical file hash cannot.

**Revised interpretation of a September 2025 observation.** Initial review of the September 2025 honeypot logs recorded 72 file-download events all originating from `172.17.0.1`, the Docker bridge gateway, and these were provisionally read as local testing activity. That reading is probably wrong. The captured artifact for those events carries the hash above, meaning they were deliveries of the Outlaw key rather than operator testing. The uniform gateway source address is better explained by the Cowrie container running on a Docker bridge network at that time, causing NAT to rewrite every source address to the gateway and destroying attacker attribution. The current deployment uses host networking, which preserves real source addresses. This explanation is inferred from the networking configuration rather than proven from a retained container config, and is recorded as such.

**Campaign variants.** The August 2026 session executed only the two key-planting commands before disconnecting, without the password change, competitor removal, or system fingerprinting observed in longer sessions from the same campaign. The campaign therefore appears to run at least two modes: a minimal backdoor-only variant and a full nineteen-command sequence. The client string in that session was `SSH-2.0-libssh_0.9.6`, a programmatic SSH library rather than an interactive client, and inter-command gaps of 3 to 5 milliseconds are consistent with scripted execution. The credential used was `root` with the single-character password `w`.

**Analysis.** The same threat actor, using unchanged tooling, has continuously targeted this infrastructure across a host rebuild and eleven months of elapsed time.

Two conclusions follow. First, the tooling is static: the key material has not been rotated despite being trivially fingerprintable and publicly documented, indicating an operation optimised for scale rather than evasion. Second, and more important for interpreting the original incident, targeting is **opportunistic rather than directed**. Roughly 27% of all command-executing sessions against the honeypot belong to this single campaign. Nothing in the data suggests this infrastructure was selected; it was reachable, and the campaign is indiscriminate.

This reframes the original compromise. It was not a targeted intrusion against a specific operator. It was a mass campaign that succeeded once against one misconfigured host, and which has continued attempting the same thing at scale, against the same address space, every day since.

### Finding 6: Recovered Perl IRC bot component and capability analysis

- Severity / Confidence: High / Confirmed
- MITRE ATT&CK: T1059 (Command and Scripting Interpreter), T1071 (Application Layer Protocol), T1046 (Network Service Discovery), T1498 (Network Denial of Service), T1105 (Ingress Tool Transfer), T1036.004 (Masquerading: Masquerade Task or Service)

**Evidence.** A 27,795-byte Perl script was recovered from the compromised host prior to rebuild and retained. Key configuration values:

```
my $processo = 'edac0';
$servidor = '0xB32B8B53'    # decodes to 179.43.139.83
my $porta  = '443';
my @canais = ("#001");
my @adms   = ("molly","polly");
my $VERSAO = '0.2a';
```

The C2 address is stored as an obfuscated hexadecimal integer rather than plaintext. Decoding `0xB32B8B53` yields `179.43.139.83`. This matches an IOC independently extracted during Phase 1 by regular expression search over the decoded payload.

Documented capabilities, derived from reading the full source:

| Capability | Implementation |
|---|---|
| Remote command execution | `shell()` runs arbitrary commands, returns output over IRC in rate-limited chunks |
| Network scanning | `portscan` (fixed port list) and `fullportscan` (arbitrary range) |
| Denial of service | UDP flood, subnet-wide UDP flood, and a raw-socket flooder issuing ICMP/IGMP/UDP/TCP across all 65535 ports |
| Payload retrieval | `download` function plus a full IRC DCC file transfer implementation |
| Secondary access | `conback` connect-back reverse shell, independent of the IRC channel |
| Process masquerading | Sets its own process name to `edac0` |
| Client spoofing | Reports its IRC version as `mIRC v6.16` |
| Signal resistance | Ignores SIGINT, SIGHUP, SIGTERM, SIGCHLD |

**Analysis.** This component provides interactive operator control, distinct from the automated mining and propagation components in Finding 2. Its architecture is an IRC channel backdoor: the implant joins a channel and accepts commands from specific privileged nicknames, allowing one operator to control many compromised hosts through a single interface.

Two design decisions are notable. Port 443 is used for plaintext IRC rather than TLS, chosen so casual port-based inspection reads the traffic as HTTPS. The `conback` reverse shell exists as a fallback access path independent of the IRC infrastructure, meaning takedown of the C2 channel would not necessarily remove operator access.

Source comments and user-facing strings are predominantly Portuguese (`Estatísticas ativadas`, `Diretório inexistente`, `Nenhuma porta aberta foi encontrada`). One string in the flood status output uses `secunde`, which is Romanian. This mixture is consistent with tooling forked and modified across multiple communities over time, and is treated here as an indicator of code lineage rather than operator nationality.

**Relationship to the C2 in Finding 2.** The beaconing process observed live connected to `179.43.139.85`. The C2 decoded from this script is `179.43.139.83`. Two addresses within the same `/24`, which supports a common infrastructure provider or allocation but is not by itself proof of a single operator.

### Finding 7: Attribution to the Outlaw (Dota) threat cluster

- Confidence: Confirmed as a TTP match
- MITRE ATT&CK: not applicable (attribution finding)

**Evidence.** Observed indicators compared against published research on the group tracked as Outlaw, also referred to as Dota, first documented by Trend Micro in 2018 and subsequently analysed by Kaspersky:

| Documented indicator | Observed in this incident | Match |
|---|---|---|
| SSH key comment `mdrfckr` | `mdrfckr` | Exact |
| Hidden directory `.configrc5` | `.configrc7` | Same pattern, different suffix |
| Subdirectories `a/` and `b/` | `a/kswapd00`, `a/upd`, `b/sync` | Exact |
| Process masquerade as `kswapd0` | `.kswapd00`, `kauditd0`, `kthreadad` | Exact technique |
| Masquerade as `rsync` | `/tmp/.X2t-unix/.rsync/c/` | Exact |
| Obfuscated Perl IRC bot backdoor | recovered Perl bot | Exact |
| Modified XMRig miner, UPX packed | 2.2 MB binary at 165% CPU | Consistent, unverified |
| C2 `45.9.148.99` (Kaspersky case) | `179.43.139.83` / `.85` | Differs |

**Analysis.** Seven of eight documented indicators match, six exactly. The single divergence is the C2 address, which is expected: infrastructure is routinely rotated between campaigns while tooling and technique remain stable. A match on infrastructure would in fact be weaker evidence than a match on behaviour.

The miner match is recorded as **consistent but unverified**. Size, hidden placement, resource profile and masquerading name align with the documented XMRig variant, but the sample was destroyed with the host and no hash comparison or static analysis was possible. This is stated as a limitation rather than presented as a confirmed match.

Two supporting observations. The directory suffix appears to increment across campaign iterations; published research documents `.configrc5`, this incident involved `.configrc7`, loosely placing it as a later variant than the analysed samples. Separately, Kaspersky's documented incident occurred in Brazil, consistent with the Portuguese-language artifacts noted in Finding 6, though corroborative and weak on its own for the code-lineage reasons already stated.

**Scope of this attribution.** This finding asserts that observed techniques match a documented threat cluster. It makes no claim regarding the identity, nationality, location, or affiliation of any operator. Given Finding 5, the appropriate interpretation is that this infrastructure was affected by a large-scale opportunistic campaign, not selected as a target.

## Indicators of Compromise

Attacker-side only. Provided for defensive use.

| Type | Value |
|---|---|
| C2 (recovered from Perl bot) | `179.43.139.83:443` |
| C2 (observed live beacon) | `179.43.139.85:80` |
| Attacker source address | `91.132.138.238` |
| SSH key comment | `mdrfckr` |
| Planted `authorized_keys` artifact (SHA256) | `a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2` (389 bytes, OpenSSH RSA public key) |
| Observed client string | `SSH-2.0-libssh_0.9.6` |
| Hidden directory | `~/.configrc7/` with `a/` and `b/` subdirectories |
| Staging directory | `/tmp/.X2t-unix/.rsync/` |
| Payload paths | `/tmp/.kswapd00`, `/var/tmp/.kswapd00`, `~/.configrc7/a/kswapd00` |
| Component scripts | `~/.configrc7/a/upd`, `~/.configrc7/b/sync` |
| Process names | `kauditd0`, `kthreadad`, `edac0` |
| IRC channel / operators | `#001`, nicknames `molly`, `polly` |
| Command prefix (high signal) | `cd ~; chattr -ia .ssh; lockr -ia .ssh` |

## Recommendations

### Applied during remediation

- Full operating system reinstall rather than in-place cleaning, given confirmed root-level access and uncertain persistence coverage.
- SSH key rotation, with the attacker-planted key removed and a newly generated Ed25519 keypair installed.
- Password authentication and direct root login disabled.

### Preventive

**1. Verify effective SSH configuration rather than file contents.** The root cause was invisible to inspection of `/etc/ssh/sshd_config`. Configuration should be validated with `sshd -T`, which reports runtime values actually in force after all includes resolve, and rechecked after any provider image deployment or cloud-init run.

**2. Implement outbound connection monitoring.** The most significant gap this incident exposed. The host maintained several hundred concurrent outbound SSH connections for days, and detection came entirely from an external party. A threshold alert on outbound connection count, or on outbound port 22 connections from a host with no legitimate reason to originate them, would have reduced detection time from days to minutes. Inbound monitoring was in place and functioning; outbound was not monitored at all.

**3. Constrain workload resources so a single compromised process cannot starve the host.** The honeypot was not the entry vector here; access came through the host's own misconfigured SSH service, and Cowrie's containment was never breached. The actual cost of co-locating workloads was a shared failure domain: when the mining component consumed 165% CPU and two thirds of available memory, the co-hosted application was starved and became unresponsive.

The mitigation is resource isolation rather than physical separation. Per-container CPU and memory limits prevent any single workload, compromised or otherwise, from exhausting the host, converting an outage into a bounded resource alert. This is free and requires no additional infrastructure. Where full separation is preferred, hosting the production workload on a separate platform achieves it at no cost via commodity free tiers, but a second server is not required to address the failure observed here.

**4. Snapshot before remediating, where the tradeoff allows.** Remediation speed was correctly prioritised, since the host was actively attacking third parties. However, the provider's snapshot facility would have permitted disk preservation at negligible time cost, which would have made the mining binary available for analysis and removed the largest evidence limitation in this report.

**5. Add campaign-specific detection.** The `mdrfckr` key comment and the `chattr -ia .ssh` command prefix are stable, known indicators for this campaign. Alerting on them directly surfaces campaign activity without manual log review.

## Lessons Learned

**Verify effective state, not intended state.** The most consequential finding was a configuration setting that was correctly applied, visibly present in the expected file, and completely inert. Reading configuration files confirms intent. Only querying the running service confirms reality. This generalises well beyond SSH.

**Detection failed in one direction only.** Inbound monitoring was configured and working. Outbound was not monitored at all, and that is precisely the direction that mattered once the host was compromised. Monitoring designed around "who is attacking me" does not detect "what is my host attacking," and the second question is the one that generates provider abuse reports and service suspension.

**Containment before understanding persistence wastes the attempt.** Killing the process and deleting the visible binary appeared to work and did not. Only after the implant returned did the investigation turn to persistence mechanisms, which is where the actual fix was. The correct order is: identify persistence first, then remove the payload, because a payload removed while its scheduler remains is a payload that reinstalls itself.

**A compromised system cannot be trusted to describe itself.** Rescue mode analysis, with the disk mounted as secondary storage under a known-clean operating system, made the persistence hunt reliable. Every command run on the live compromised host had been executed by binaries of unverified integrity.

**Assumption is not attribution.** Two of the three Phase 1 errors came from labelling activity as hostile based on proximity to known-hostile events rather than on evidence. One, cryptographically impossible, would have been caught by asking a single question: what would have to be true for this to be the attacker's key? The habit worth building is deriving attribution from evidence and stating confidence explicitly, rather than assigning it by association.

**One log source is not corroboration.** The third error placed the compromise in a window contradicted by a file timestamp sitting in the same evidence set. Authentication logs alone supported the wrong conclusion; authentication logs cross-referenced against filesystem metadata did not.

**Attack vector and blast radius are separate problems requiring separate fixes.** The vector was a configuration precedence bug in SSH. The blast radius was unbounded resource consumption, which took a co-hosted application offline. These are unrelated failures, and fixing either would have left the other intact. Conflating them produces the wrong remediation, typically an expensive architectural change where a configuration control was what was needed. The correct question after an incident is not only "how did they get in," but separately, "once in, what could they reach and how much could they consume."

**Continued collection answered a question the incident could not.** At the time of the compromise there was no way to determine whether the host had been specifically targeted or opportunistically caught. Six months of subsequent honeypot data from the replacement infrastructure resolved it decisively: roughly 27% of all command-executing sessions belong to this same campaign, using an unchanged key. That is a stronger and more useful conclusion than anything available during the incident itself, and it existed only because collection continued after remediation.

## References

- Kaspersky Securelist, "Outlaw botnet" incident analysis: https://securelist.com/outlaw-botnet/116444/
- Trend Micro, original Outlaw group identification (2018)
