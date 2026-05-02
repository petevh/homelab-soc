# Homelab Threat Management Platform

## Project Overview

A self-hosted Security Operations Centre (SOC) lab built on Proxmox, combining a SIEM (Wazuh) and Threat Intelligence Platform (MISP) to provide practical experience with threat intelligence workflows, IOC management, and security monitoring. Secondary goal is building a consulting portfolio demonstrating SMB-scale security architecture.

This is infrastructure-as-code and configuration management — deployment scripts, Ansible playbooks, configuration templates, custom Wazuh rules, and MISP feed configurations. Not application development.

## Context & Goals

- **Primary driver:** Professional context involves interaction with threat intelligence teams and regulators (including DFSA/DIFC); need hands-on experience consuming and applying threat intelligence data practically
- **Reference environment:** Access to DFSA-provided TIP in DIFC — this homelab mirrors that capability for learning
- **Monitored environment:** M365 Business Premium tenant (separate repo: `m365-admin`) — Wazuh integrates with M365 via Graph API and Office 365 Management API
- **Consulting angle:** Architecture mirrors what you'd recommend to SMBs who need security monitoring beyond basic M365 tools but can't justify Sentinel costs
- **YARA:** Some regulators expect YARA rule ingestion capability — MISP handles this natively; document compliance posture

## Architecture

```
External Threat Feeds (CIRCL, abuse.ch, AlienVault OTX, CISA, DFSA)
    ↓
MISP (TIP — VM on Proxmox)
    ↕ (IOC enrichment)
Wazuh Manager + Indexer (SIEM — VM on Proxmox)
    ↑ (logs & alerts)
M365 Business Premium (Graph API, Office 365 Management API)
Homelab infrastructure (Proxmox hosts, TrueNAS, network devices)
```

**Key distinction:** MISP is the TIP (stores and manages threat intelligence). Wazuh is the SIEM (collects logs, detects threats). They are complementary, not alternatives. Wazuh consumes IOCs from MISP to enrich detections; Wazuh can feed new IOCs back to MISP.

## Repository Structure

```
threat-management-platform/
├── CLAUDE.md                        # This file
├── README.md
├── docs/
│   ├── architecture.md              # Full architecture diagram and decisions
│   ├── misp-wazuh-integration.md    # Integration configuration reference
│   ├── feed-inventory.md            # Active feeds, sources, update frequency
│   ├── yara-compliance.md           # YARA rule ingestion for regulatory posture
│   └── mitre-attack-mapping.md      # Detection coverage mapped to ATT&CK
├── misp/
│   ├── deploy/
│   │   ├── install.sh               # MISP installation script (Ubuntu 24.04)
│   │   └── post-install.sh          # Post-install configuration automation
│   ├── config/
│   │   ├── feeds.json               # Feed definitions for import via API
│   │   └── server-settings.md       # Key settings reference (not secrets)
│   ├── feeds/
│   │   ├── enabled-feeds.md         # Active feed inventory
│   │   └── custom-feeds/            # Any custom/private feed configs
│   └── yara/
│       └── regulatory/              # YARA rules from regulatory sources (DFSA etc.)
├── wazuh/
│   ├── deploy/
│   │   ├── install-manager.sh       # Wazuh Manager + Indexer install
│   │   └── install-agent.sh         # Agent install template
│   ├── rules/
│   │   ├── m365/                    # Custom rules for M365 log sources
│   │   │   ├── exchange-rules.xml
│   │   │   ├── entra-rules.xml
│   │   │   └── defender-rules.xml
│   │   ├── homelab/                 # Rules for Proxmox, TrueNAS, OPNsense
│   │   └── custom/                  # General custom detection rules
│   ├── decoders/
│   │   └── m365-decoders.xml        # Log format decoders for M365 sources
│   ├── integrations/
│   │   ├── misp-integration.md      # MISP connector configuration
│   │   └── m365-integration.md      # Graph API / O365 Management API setup
│   └── dashboards/
│       └── m365-dashboard.json      # Wazuh dashboard export for M365 monitoring
├── ansible/                         # Automation for VM provisioning and config
│   ├── inventory/
│   │   └── hosts.yml                # Proxmox VM inventory
│   ├── playbooks/
│   │   ├── deploy-misp.yml
│   │   ├── deploy-wazuh.yml
│   │   └── configure-integrations.yml
│   └── roles/
│       ├── misp/
│       └── wazuh/
└── scripts/
    ├── ioc-lookup.py                # Query MISP for IOC lookups
    ├── feed-health-check.sh         # Verify all feeds are updating
    └── wazuh-rule-test.sh           # Test custom rules against sample logs
```

## Components

### MISP (Threat Intelligence Platform)

**VM spec:** Ubuntu 24.04 LTS, 4GB RAM, 2 vCPUs, 50GB disk

**Purpose:** Store, manage and share threat intelligence — IOCs, TTPs, threat actors, campaigns. Primary interface for consuming regulatory threat intelligence (DFSA feeds).

**Key capabilities in use:**
- Feed ingestion (STIX/TAXII, CSV, freetext)
- YARA rule storage and management (regulatory compliance)
- IOC correlation and enrichment
- API exposure for Wazuh integration
- MITRE ATT&CK framework tagging

**Feeds (baseline):**
- CIRCL OSINT Feed — general purpose, well-curated
- abuse.ch URLhaus — malicious URLs
- abuse.ch Feodo Tracker — botnet C2
- AlienVault OTX — requires free API key
- CISA Known Exploited Vulnerabilities
- DFSA regulatory communications (manual import)

**YARA:** MISP natively supports YARA rule objects. Regulatory-sourced YARA rules stored under `misp/yara/regulatory/` and imported into MISP for tracking and compliance documentation.

---

### Wazuh (SIEM)

**VM spec:** Ubuntu 24.04 LTS, 8GB RAM, 4 vCPUs, 100GB disk
*(Wazuh Manager + Indexer/OpenSearch co-located for homelab scale)*

**Purpose:** Centralised log collection, threat detection, and alerting. Primary visibility into M365 and homelab infrastructure.

**Log sources:**
- M365 via Office 365 Management API (Exchange, SharePoint, OneDrive, Teams audit logs)
- Entra ID sign-in and audit logs via Graph API
- Microsoft 365 Defender alerts via Graph Security API
- Proxmox host logs (syslog)
- TrueNAS (syslog)
- OPNsense firewall logs

**M365 limitations (Business Premium):**
- No Defender for Endpoint P2 — no advanced hunting or raw endpoint telemetry via API
- Limited to audit logs and security alerts available via Graph API
- Custom detection rules cannot leverage full EDR dataset

**MISP integration:**
- Wazuh queries MISP API to check IOCs from logs against known threat intelligence
- Generates enriched alerts when known-bad indicators appear in logs
- Active response rules can be triggered on high-confidence IOC matches

---

## Key Integration: Wazuh ↔ M365

Authentication via **app registration** in Entra ID (certificate-based, not client secret):
- `AuditLog.Read.All` — audit logs
- `SecurityEvents.Read.All` — security alerts
- `MailboxSettings.Read` — Exchange metadata
- `Reports.Read.All` — usage reports

Credentials stored in Wazuh agent environment — never in repo.

---

## Development & Deployment Approach

This repo is primarily **configuration and automation**, not application code. The workflow is:

1. Document intended configuration in `docs/`
2. Script the deployment in `deploy/` or `ansible/`
3. Export and version custom rules and dashboards
4. Test rule changes against sample logs before deploying to live Wazuh instance
5. `main` branch = what's deployed and running

**Never commit:**
- API keys or tokens (MISP auth key, Graph API credentials, OTX API key)
- Wazuh manager/indexer passwords
- Any `.env` files — provide `.env.example` templates only

---

## Proxmox Infrastructure Notes

- Both VMs on same Proxmox host (HP EliteDesk 800 G6, i5-10500T, 64GB+ RAM)
- MISP and Wazuh on isolated management VLAN where possible
- Proxmox Backup Server snapshots scheduled for both VMs
- Tailscale on both VMs for remote access without exposing ports

---

## Regulatory & Compliance Context

- DFSA (Dubai Financial Services Authority) is the relevant financial regulator
- DIFC environment has access to DFSA-provided TIP — this homelab mirrors that capability
- YARA rule ingestion is an emerging regulatory expectation — tracked in `docs/yara-compliance.md`
- MITRE ATT&CK framework mapping maintained in `docs/mitre-attack-mapping.md` to demonstrate coverage

---

## Related Repos

- `m365-admin` — M365 PowerShell scripts and policy management (Wazuh integration config lives here too, mirrored in `wazuh/integrations/m365-integration.md`)
- `sunsynk-monitor` — unrelated home energy project
