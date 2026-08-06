# Security Casefiles

Write-ups from real security investigations on servers I own.

Hey all! I'm Alan, an engineer who enjoys researching and investigating attacker behavior, malware, and whatever else turns up on my servers, with AI helping me get to the bottom of things.

I currently run an SSH honeypot on a VPS I own and built a SIEM to watch it. This repo is where I write up what I find.

My background is production engineering, mostly auth, RBAC, audit logging and API security, so I tend to build my own tooling. I've also got a Criminal Justice degree, and the investigative side of it carries over way more than I expected.

## Status

Three cases up so far:

- `cases/2025-09-08-outlaw-botnet-compromise/`: a real compromise of a VPS I own, used to brute-force at least 140 third-party systems until my provider issued an abuse notice. Root cause was a cloud-init drop-in silently re-enabling SSH password authentication. Attributed to the Outlaw (Dota) botnet, and correlated eleven months later against 70,626 sessions from the same actor on the replacement host's honeypot. Includes three of my own original conclusions that later evidence overturned.
- `cases/2026-07-26-neutron-c2-honeypot/`: a two-stage botnet dropper campaign traced against my own SSH honeypot.
- `cases/2026-08-04-persistent-fingerprinting-campaign/`: a five-week credential and fingerprinting campaign from a single actor, including evidence it actively detects and avoids the honeypot.

More on the way.

## Methodology

Every case here follows a consistent structure and maps to established frameworks rather than ad hoc write-ups:

- MITRE ATT&CK: adversary tactics and techniques, named by ID.
- PTES: pentest methodology shape, applied even to solo practice work.
- Diamond Model of Intrusion Analysis: adversary, infrastructure, capability, and victim, for CTI-style write-ups.
- Chain-of-custody principles: evidentiary rigor for OSINT and forensics work.

## Links

- Portfolio: [alanarias.com](https://alanarias.com)
- X: [@Alancodes11](https://x.com/Alancodes11)
