# CLAUDE.md - Amsterdam IDC Network Migration Project

## Project Overview

This project involves the migration of Amsterdam and Singapore colocation data centers from legacy Cisco Catalyst 3850 switch stacks to a modern Cisco Nexus-based architecture.

## Project Goals

1. Replace end-of-life Cisco Catalyst 3850 switches
2. Implement scalable Nexus-based architecture (core/aggregation and access layers)
3. Support SD-WAN transformation, Cisco DNA Center, and firewall refresh initiatives
4. Expand 10G/25G port capacity significantly
5. Consolidate legacy top-of-rack (ToR) switches into new access layer

## Working Context

### Current State
- **Primary Site Focus:** Amsterdam IDC (AMIDC)
- **Core Device:** AMIDCnsm0101 - 6-member Catalyst 3850 stack
  - 2x WS-C3850-24XS (48x 10G SFP+ total)
  - 4x WS-C3850-48P (192x 1G PoE total)
- **Role:** Central aggregation hub for all WAN, security, compute, storage, and voice infrastructure

### Target State
- **Core/Aggregation:** 2x Cisco Nexus N9K-C93240YC-FX2 per site (AMIDCnsm0101a, AMIDCnsm0101b)
- **Access Layer Fiber:** 2x Cisco Nexus N9K-C93180YC-FX3 per site (AMIDCnsm0103a, AMIDCnsm0103b)
- **Access Layer Copper:** 2x Cisco Nexus N9K-C93108TC-FX3 per site (AMIDCnsm0102a, AMIDCnsm0102b)

## Key Documentation

### Existing Files
1. **Executive Summary.txt** - High-level project overview and objectives
2. **Current Network Documentation.md** - Comprehensive current state documentation (master reference)
3. **Deep Technical Analysis.md** - Detailed technical deep-dive with all discoveries
4. **Operational State Analysis.md** - Live operational state from show commands
5. **SD-WAN Connectivity Summary.md** - Complete SD-WAN architecture and port mappings
6. **CRITICAL_FINDINGS_UPDATE.md** - Important corrections (SD-WAN DIA circuits on "reserved" ports)
7. **AMIDCnsm0101.txt** - Full running configuration of current 3850 stack (3006 lines)
8. **amidc show commands.txt** - Show command outputs (13078 lines)
9. **AMIDCnsm0101_additional_Show_commands.txt** - Additional show commands (interface descriptions, VLAN brief)
10. **Eaton SD-WAN IP Inventory_V1.xlsx** - SD-WAN port mappings and IP allocations
11. **AMIDC HLD.png** - Current high-level network design diagram
12. **AMIDC New HLD.png** - Future state network design diagram
13. **Internet connectivity.png** - Detailed internet connectivity topology

### Network Architecture Summary

**Connectivity Types:**
- **AT&T AVPN:** 4x OSPF links via trunk ports Te1/0/10 (VLANs 550-551) and Te2/0/10 (VLANs 552-553) to NLEACOAMS0011H/0012H
- **Internet:** Dual 10G links to AT&T ADIG routers (NLEACEAMS0001R/0002R) - Layer 2 only via VLAN 3
- **SD-WAN:** Dual routers (Amidcnrm0101/SDW1 and Amidcnrm0102/SDW2)
  - **10 active 10G ports total:**
    - 4x DIA circuits (Direct Internet Access via VLAN 3): Te1/0/7, Te1/0/17, Te2/0/7, Te2/0/17 - 24Gbps total
    - 2x Management: Te1/0/11 (SDW1), Te2/0/11 (SDW2)
    - 4x Service LANs: Po50 (SDW1), Po51 (SDW2), Po52 (SDW1 B2B), Po53 (SDW2 B2B)
  - **BGP Sessions:** SDW1: 10.253.238.46 (VLAN 622), SDW2: 10.253.239.46 (VLAN 632) - AS 65520
  - **2x 1G Management:** Gi5/0/3 (SDW1), Gi6/0/3 (SDW2)

**Key Infrastructure:**
- 6x Wireless LAN Controllers (4x 1G, 2x 10G)
- 2x BigIP Load Balancers (active - 10G dual-homed)
- ADX Load Balancers (decommissioned)
- 2x Internal Firewalls (EMEAFW1/2 - Checkpoint)
- AVTS Edge Firewalls (emeaavtsfw1/2)
- VxRail 4-node UC cluster with 2x Nexus 3K ToR switches (to be retired)
- 3-node Cisco DNA Center cluster (12x 10G + 3x 1G ports)
- Voice/UC infrastructure (CUBE/SBC, Avaya, Cisco UC, Teams)

**Routing:**
- OSPF Process 10, Area 0, Router ID 10.253.9.60
- BGP AS 64721 with 2 peer sessions (SD-WAN only)
- BFD enabled for fast convergence

**Critical VLANs:**
- VLAN 3: Internet (Layer 2 only - AT&T ADIG routers + SD-WAN DIA circuits)
- VLAN 10: 151.110.239.0/24 - Datacenter Internal (SVI: .254)
- VLAN 61: 172.18.61.0/24 - DC Utility Storage
- VLAN 62: 172.18.62.0/25 - DC Cluster Heartbeat
- VLAN 63: 172.18.62.128/25 - DC iLO/OOB
- VLAN 163: 151.110.163.0/24 - DC Production
- VLAN 555: 10.253.0.0/25 - Network Management (SVI: .1)
- VLANs 550-553: AT&T AVPN OSPF links (SVIs with /30 subnets)
- VLANs 560, 562: Business partner VPN transit (Layer 2 only - terminate on firewalls)
- VLANs 574, 591: DNA Center (Enterprise + Intracluster)
- VLANs 620-624: SDW1 transport and service VLANs
- VLANs 630-634: SDW2 transport and service VLANs
- VLAN 1502-1504: VxRail/VCE management, ESXi, vMotion

## Instructions for Claude

### When Working on This Project

1. **Always consult Current Network Documentation.md first** - It contains the comprehensive current state understanding
2. **Reference diagrams** - Visual topology in PNG files provides context
3. **Use AMIDCnsm0101.txt** - For specific configuration details and exact syntax
4. **Understand dependencies** - Changes must account for:
   - OSPF adjacencies (4x AVPN links via trunk ports Te1/0/10, Te2/0/10)
   - BGP sessions (2x SD-WAN only - NO BGP to firewalls, use static routes)
   - BFD timers and authentication (OSPF + BGP)
   - Port-channel configurations (Po50-53 for SD-WAN critical)
   - SD-WAN DIA circuits (4x 10G ports carrying production internet traffic)
   - VLAN spanning across multiple infrastructure devices
   - Trunk ports carrying multiple services (AVPN trunk carries OSPF + partner VPNs + SD-WAN transport)

### Configuration Standards

**Naming Conventions:**
- Hostnames: `<SITE>IDC<device-type><sequence>` (e.g., AMIDCnsm0101)
- Loopbacks: Loopback0 for OSPF Router ID
- Port-channels: Numbered sequentially, documented with descriptions
- VLANs: Named descriptively with purpose and subnet info

**Security Requirements:**
- TACACS+ authentication (servers: 10.251.252.33, 10.251.253.33)
- MD5 authentication on OSPF AVPN links
- BGP password authentication
- BFD for sub-second convergence
- BPDU Guard and PortFast on access ports

**High Availability:**
- All critical devices dual-homed via port-channels
- STP priority hierarchy (see below for complete strategy)
- BFD enabled on BGP sessions
- Redundant routing paths (OSPF ECMP via 4 links)

**Spanning Tree Priority Strategy (CRITICAL):**
- **Old 3850:** Priority 8192 (current root, stays root through Phase 2 & Phase 3)
- **New cores (Phase 2-3):** Priority 16384 (secondary root initially)
- **New 0101a (Step 3.12):** Priority **4096** (becomes primary root - NOT 8192 to avoid tie!)
- **New 0101b (Step 3.12):** Priority 8192 (becomes secondary root)
- **Old 3850 (Step 3.12):** Priority 32768 (demoted)
- **Access primary (0102a/0103a):** Priority 24576 (tertiary, never changes)
- **Access secondary (0102b/0103b):** Priority 28672 (quaternary, never changes)

**Why Priority 4096 (NOT 8192):**
- Old 3850 currently at 8192
- If new 0101a also 8192 = TIE → falls to MAC address election (unpredictable)
- Priority 4096 < 8192 = guaranteed deterministic root election
- Complete hierarchy: 4096 < 8192 < 16384 < 24576 < 28672 < 32768

### Migration Approach

**Strategy:** Phased migration with Layer 2 interconnection via 1G port bundles
1. Stage and configure new Nexus switches offline (priority 16384 keeps 3850 as root)
2. Install physically and establish management connectivity
3. **Create L2 port-channels using 1G copper ports** between old 3850s and new Nexus switches
   - Use Gi3/0/1, Gi3/0/2, Gi4/0/1, Gi4/0/2 → 0102a Eth1/21-22, 0102b Eth1/21-22
   - 8Gbps aggregate L2 connectivity (Po200 / vPC 200)
   - All 10G ports are in production (48/48 allocated, including SD-WAN DIA circuits)
4. Validate STP topology and root bridge (3850 stays at priority 8192, new cores at 16384)
5. Migrate non-critical services first (monitoring, management)
6. Migrate redundant services one-at-a-time (keep pairs active)
7. Migrate L3 functions (SVIs, OSPF, BGP) to new Nexus core switches
8. Migrate critical WAN services (AVPN, SD-WAN, Internet) in Phase 3
9. **Step 3.12: Promote new cores to STP root** (0101a→4096, 0101b→8192, 3850→32768)
10. Decommission old 3850 stack and VxRail ToR switches

**Critical Considerations:**
- Maintain OSPF adjacencies during migration (VLANs 550-553 via trunk ports Te1/0/10, Te2/0/10)
- BGP sessions must not flap (692 prefixes per SD-WAN router serving global branches)
- SD-WAN DIA circuits must remain active (24Gbps total internet capacity)
- BFD timers must be preserved (300ms detection time)
- Zero downtime for production traffic
- DNA Center cluster quorum (need 2/3 nodes operational)
- VxRail ToR switches provide 40Gbps aggregate - migrate one at a time
- Static routes to firewall (151.110.239.1) must remain - NO BGP session needed
- Validate each step before proceeding

### Tasks Claude Should Help With

**Configuration Generation:**
- New Nexus switch base configurations
- VLAN migration mappings
- Port-channel configurations for device moves
- OSPF and BGP migration configs
- BFD timer preservation

**Planning:**
- Device migration order and dependencies
- Rollback procedures for each phase
- Validation checklists per phase
- Risk assessment and mitigation

**Documentation:**
- Migration runbooks
- Pre/post validation checks
- Configuration comparisons (old vs new)
- IP address and VLAN mappings

**Analysis:**
- Identify dependencies between devices
- Map current connections to new switch ports
- Analyze routing table changes
- Review STP topology changes

### Restrictions and Cautions

**DO NOT:**
- Make assumptions about undocumented VLANs or connections
- Assume "reserved" ports are available (all 48x 10G ports are in production)
- Suggest using 10G ports for L2 interconnect (use 1G bundles instead)
- Configure BGP to firewalls (use static routes instead - ~100+ routes to 151.110.239.1)
- Suggest downtime approaches when zero-downtime is possible
- Bypass authentication or security features
- Disable BFD or other HA features during migration
- Remove VLANs without verifying they're unused
- Disrupt SD-WAN DIA circuits (Te1/0/7, Te1/0/17, Te2/0/7, Te2/0/17)
- **Set new core to STP priority 8192** (ties with 3850, use 4096 instead!)
- Change STP root before gateway migration (wait for Step 3.12)

**DO:**
- Always validate current state before suggesting changes
- Provide rollback procedures for every change
- Consider impact on BGP and OSPF sessions
- Account for STP convergence during L2 changes
- Preserve all authentication and security configurations
- Test in non-production VLANs when possible

### File Handling

**When reading AMIDCnsm0101 running state.txt:**
- File is very large (865KB)
- Use offset/limit parameters to read specific sections
- Use Grep tool for targeted searches instead of reading entire file

**When analyzing configurations:**
- Use Grep for interface searches: `^interface`
- Use Grep for routing: `^router (ospf|bgp)`
- Use Grep for VLAN searches: `^vlan \d+`
- Read specific line ranges when you know the location

### Communication Style

- Be concise and technical
- Provide specific line numbers when referencing configuration files
- Use tables for comparing configurations or mapping data
- Include risk assessment for suggested changes
- Always provide validation steps after changes
- Flag breaking changes or potential downtime explicitly

## Project Status

**Current Phase:** ✅ Documentation Complete - Ready for Configuration Generation

**Completed:**
- ✅ Current state fully documented and analyzed
- ✅ All operational data collected and reviewed
- ✅ SD-WAN architecture completely mapped (including DIA circuits)
- ✅ Port exhaustion understood (48/48 10G ports in production)
- ✅ Migration strategy defined (1G bundles for L2 interconnect)
- ✅ Critical dependencies identified (OSPF, BGP, BFD, DNA Center, VxRail)

**Next Steps:**
1. Generate new Nexus switch base configurations
2. Create detailed port migration matrix (old → new mappings)
3. Generate VLAN and SVI configurations for new switches
4. Create migration runbook with phase-by-phase procedures
5. Define validation checklists and rollback procedures
6. (Future) Complete Singapore site documentation

## Key Contacts and Resources

**Support:**
- AT&T Dedicated Internet: 888 613 6330 opt 2, 1
- AT&T Portal: www.att.com/expressticketing

**Network Details:**
- Management Network: 10.253.0.0/25 (VLAN 555)
- Primary Gateway: 10.253.0.1
- OSPF Router ID: 10.253.9.60
- BGP ASN: 64721

## Important Notes

### Port Allocation Reality
**All 48x 10G SFP+ ports are allocated:**
- 44 active production connections
- 4 SD-WAN DIA circuits (previously thought "reserved")
- 0 available for L2 interconnect
- **Solution:** Use 1G copper port bundles (Gi3/0/x, Gi4/0/x)

### SD-WAN DIA Circuits (CRITICAL)
**Do NOT assume Te1/0/7, Te1/0/17, Te2/0/7, Te2/0/17 are available**
- These carry 4x 6Gbps DIA circuits (24Gbps total)
- Production internet traffic via VLAN 3
- Public IPs: 195.33.34.0/27, 195.75.178.0/27
- Must remain operational during entire migration

### Routing to Firewalls
**NO BGP session to firewalls** (151.110.239.1 shows "Active" for 2y7w)
- Use ~100+ static routes instead (already configured)
- Simpler operational model
- Firewall doesn't advertise routes back

### AVPN Trunk Ports
**Te1/0/10 and Te2/0/10 are multi-service trunks:**
- Carry OSPF VLANs 550-553 (4 SVIs)
- Carry business partner VPN transit (VLANs 560, 562)
- Carry SD-WAN transport VLANs (620-624, 630-634)
- Cannot be migrated as simple P2P links

### DNA Center Requirements
**Cannot reduce port count:**
- Dual 10G per node mandatory (Enterprise + Intracluster)
- 12x 10G + 3x 1G management total
- Must maintain cluster quorum during migration

### L2 Interconnect Ports (Phase 2)
**Po200 / vPC 200 - 8Gbps aggregate:**

**CORRECTED config files (Recommended):**
```
3850 Gi3/0/1 → 0102a Eth1/21 (consecutive, matching)
3850 Gi3/0/2 → 0102b Eth1/21
3850 Gi4/0/1 → 0102a Eth1/22
3850 Gi4/0/2 → 0102b Eth1/22
```

**Non-corrected config files (Alternate):**
```
3850 Gi3/0/1 → 0102a Eth1/26 (different ports due to AVPN on Eth1/21-22)
3850 Gi3/0/2 → 0102b Eth1/31
3850 Gi4/0/1 → 0102a Eth1/27
3850 Gi4/0/2 → 0102b Eth1/47
```

**Use CORRECTED files for deployment** - consecutive matching ports (21-22)

### Internet Uplink Ports (Phase 3)
**Specific port assignments:**
```
Primary:   3850 Te1/0/13 → NLEACEAMS0001R Te0/3/0 → 0101a Eth1/2 (VLAN 3)
Secondary: 3850 Te2/0/13 → NLEACEAMS0002R Te0/3/0 → 0101b Eth1/2 (VLAN 3)
```
- NOT generic "Te?/?" references
- Step 3.2: Move primary (Te1/0/13)
- Step 3.7: Move secondary (Te2/0/13)

## Version History

- **v1.0** (2026-04-10): Initial CLAUDE.md created with project context and instructions
- **v2.0** (2026-04-10): Major update - corrected SD-WAN port usage, removed OOB upgrade scope, added all documentation references, updated migration strategy
- **v3.0** (2026-04-21): Added complete STP priority strategy (priority 4096 for new primary root), L2 interconnect port details (Po200/vPC 200), and internet uplink specific ports (Te1/0/13, Te2/0/13)
