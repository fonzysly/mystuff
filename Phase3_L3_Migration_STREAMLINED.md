# Phase 3: L3 Migration - Technical Runbook (STREAMLINED)

**Risk Level:** HIGH - Production routing changes
**Expected Downtime:** 1-5 seconds during gateway cutover
**Duration:** 6-8 hours

---

## Migration Overview

### Objectives
1. Move all WAN uplinks from old 3850 to new cores
2. Activate HSRP gateway IPs on new cores
3. Transfer all Layer 3 routing to new environment
4. Validate complete L3 migration
5. Promote new cores to STP root

### Critical Steps
1. **Step 3.1:** Pre-work validation
2. **Step 3.2:** Move primary internet link
3. **Step 3.3:** Move primary AVPN link
4. **Step 3.4:** Move primary SD-WAN router (SDW1)
5. **Step 3.5:** **ACTIVATE HSRP GATEWAY IPs** ⭐⭐⭐
6. **Step 3.6:** Verify static routes
7. **Step 3.7:** Move secondary internet link
8. **Step 3.8:** Move secondary AVPN link
9. **Step 3.9:** Move secondary SD-WAN router (SDW2)
10. **Step 3.10:** Shutdown old 3850 SVIs
11. **Step 3.11:** Comprehensive L3 validation
12. **Step 3.12:** Promote new cores to STP root (priority 4096)
13. **Step 3.13:** Final validation & documentation

---

## Step 3.1: Pre-Work Validation

### ⚠️ PREREQUISITE: Layer 2 Interconnect MUST Be Operational

**Verify L2 trunk before starting Phase 3:**
```
! On 3850:
show etherchannel summary | include Po200
! Expected: Po200(SU) with 4 members (Gi3/0/1-2, Gi4/0/1-2)

! On Nexus 0102a/0102b:
show port-channel summary | include Po200
show vpc 200
! Expected: Po200(SU), vPC 200 operational
```

**If Po200 is NOT operational:** STOP - Complete Phase 2 first

### Record Baselines

**On Old 3850:**
```
show ip ospf neighbor        ! Expected: 4 neighbors
show ip bgp summary          ! Expected: 2 neighbors, ~692 prefixes each
show spanning-tree summary   ! Expected: This bridge is root (priority 8192)
show ip route summary        ! Record total routes
```

**On New Cores (0101a/0101b):**
```
show vpc                     ! Expected: vPC operational
show vpc consistency-parameters global
show port-channel summary    ! Expected: Po100 (peer-link) Up, Po101-104 Up
show interface loopback0     ! Expected: 10.253.9.61 (0101a), 10.253.9.62 (0101b)
show hsrp brief              ! Expected: Init (SVIs shutdown)
```

### Configuration Backups
```
! On 3850:
copy running-config tftp://10.253.0.x/3850-pre-migration.cfg

! On new cores:
copy running-config tftp://10.253.0.x/0101a-pre-migration.cfg
copy running-config tftp://10.253.0.x/0101b-pre-migration.cfg
```

### Pre-Migration Checklist
- [ ] Old 3850: Stable, all services operational
- [ ] New switches: Healthy, vPC operational
- [ ] Backups: Completed and verified
- [ ] No active incidents
- [ ] Rollback plan reviewed

---

## Step 3.2: Move PRIMARY Internet Link

**Objective:** Move primary internet uplink from 3850 to new core 0101a

**Current:** 3850 Te1/0/13 ↔ NLEACEAMS0001R (VLAN 3)
**Target:** 0101a Eth1/2 ↔ NLEACEAMS0001R (VLAN 3)
**Risk:** LOW - Secondary path remains active

### Procedure
```
! On 3850:
configure terminal
interface TenGigabitEthernet1/0/13
  shutdown
end

! Disconnect cable from 3850 Te1/0/13
! Connect cable to 0101a Eth1/2
! Interface auto-enables
```

### Validation
```
! On 0101a:
show interface ethernet 1/2 | include protocol
! Expected: "line protocol is up"

show interface ethernet 1/2 switchport
! Expected: VLAN 3 access mode

show interface ethernet 1/2 | include rate
! Expected: Traffic in/out
```

### Quick Rollback (if needed)
Shutdown 0101a Eth1/2, reconnect to 3850 Te1/0/13, no shutdown

**Checklist:**
- [ ] 0101a Eth1/2: up/up
- [ ] Internet connectivity validated
- [ ] No errors in logs

---

## Step 3.3: Move PRIMARY AVPN Link

**Objective:** Move AVPN router NLEACOAMS0011H from 3850 to 0101a

**Current:** 3850 Te1/0/10 (trunk) ↔ NLEACOAMS0011H
**Target:** 0101a Eth1/1 (trunk) ↔ NLEACOAMS0011H
**VLANs:** 550-551, 553, 560, 562, 620-634
**OSPF:** VLANs 550, 551
**Risk:** MEDIUM - 10-20 seconds OSPF reconvergence

### Procedure
```
! On 3850:
configure terminal
interface TenGigabitEthernet1/0/10
  shutdown
end

! Disconnect trunk from 3850 Te1/0/10
! Connect trunk to 0101a Eth1/1
! Interface auto-enables
```

### Monitor OSPF Formation
```
! On 0101a:
watch show ip ospf neighbor
! Expected progression: INIT → 2-WAY → EXSTART → EXCHANGE → LOADING → FULL
! Time: 10-40 seconds

! Target state:
show ip ospf neighbor
Neighbor ID     State    Interface
10.253.9.193    FULL/    Vlan550
10.253.9.197    FULL/    Vlan551
```

### Validation
```
show ip ospf neighbor detail     ! Both neighbors FULL
show bfd neighbors               ! Sessions UP (300ms/100ms/3)
show ip route ospf               ! Routes learned from AVPN
```

**On 3850:** Should now show only 2 OSPF neighbors (VLANs 552, 553)
**Total:** 4 OSPF adjacencies maintained ✅

**Checklist:**
- [ ] OSPF neighbors 10.253.9.193, 10.253.9.197: FULL
- [ ] BFD sessions up
- [ ] Routes learned via OSPF
- [ ] Total OSPF adjacencies: 4

---

## Step 3.4: Move PRIMARY SD-WAN Router - SDW1

**Objective:** Move ALL SDW1 connections from 3850 to new cores

**⚠️ CRITICAL:** Moves 12Gbps production internet traffic (DIA circuits)

### SDW1 Connections Target

| Connection | Current 3850 | Target | Details |
|------------|-------------|---------|---------|
| DIA-1 | Te1/0/7 | 0101a Eth1/3 | VLAN 3, 6Gbps |
| DIA-2 | Te1/0/17 | 0101b Eth1/3 | VLAN 3, 6Gbps |
| Transport | - | 0101a Eth1/5 | VLAN 620 |
| Service Po1 | Po50 | vPC 1 (Eth1/9) | VLANs 621-623, BGP VLAN 622 |
| B2B MPLS | - | 0101a Eth1/13 | VLAN 624 |
| Management | Gi5/0/3 | 0102a Eth1/9 | VLAN 10, 1G |

### Procedure - DIA Circuits First
```
! Migrate DIA-1 to 0101a:
! On 3850: shutdown Te1/0/7
! Move cable to 0101a Eth1/3
! Verify: show interface ethernet 1/3 | include protocol

! Migrate DIA-2 to 0101b:
! On 3850: shutdown Te1/0/17
! Move cable to 0101b Eth1/3
! Verify: show interface ethernet 1/3 | include protocol
```

### Migrate Service LANs as vPC
```
! On SDW1 router:
configure terminal
interface Port-channel1
  shutdown
end

! Move Te0/0/3 cable to 0101a Eth1/9
! Move Te0/0/4 cable to 0101b Eth1/9

! On SDW1 router:
configure terminal
interface Port-channel1
  no shutdown
end
```

### Monitor BGP Formation
```
! On 0101a:
watch show ip bgp summary
! Expected: 10.253.238.46 (SDW1) transitions from Idle → Active → Established
! Time: 30-90 seconds

! Target state:
show ip bgp summary | include 10.253.238.46
Neighbor        AS    State    PfxRcd
10.253.238.46 65520  Estab    692
```

### Complete Migration
Migrate Transport (VLAN 620), B2B (VLAN 624), and Management (VLAN 10) following same pattern.

**Checklist:**
- [ ] DIA circuits: Both operational (12Gbps total)
- [ ] BGP neighbor 10.253.238.46: Established, 692 prefixes
- [ ] BFD to BGP neighbor: UP
- [ ] vPC 1: Operational
- [ ] All SDW1 ports: up/up

---

## Step 3.5: ACTIVATE HSRP GATEWAY IPs ⭐⭐⭐

**Objective:** Activate all SVIs and HSRP on new cores - THIS IS THE L3 CUTOVER

**Risk:** VERY HIGH - 1-5 second gateway failover
**Expected Impact:** Brief interruption for all internal traffic

### ⚠️ CRITICAL MOMENT - Team Ready

**Communication:** "Beginning L3 gateway cutover. 1-5 second interruption expected."

### Un-Shutdown ALL SVIs

**On 0101a:**
```
configure terminal
interface vlan 10
  no shutdown
interface vlan 61
  no shutdown
interface vlan 62
  no shutdown
interface vlan 63
  no shutdown
interface vlan 163
  no shutdown
interface vlan 555
  no shutdown
! Continue for all SVIs (550-553, 560, 562, 574, 591, 1502-1504, 620-624, 630-634)
end
```

**On 0101b:** Repeat same commands for all SVIs

### Monitor HSRP Formation
```
! On 0101a:
watch show hsrp brief
! Expected: All VLANs transition to Active (priority 110)

! On 0101b:
watch show hsrp brief
! Expected: All VLANs transition to Standby (priority 100)
```

**Formation time:** 10-30 seconds

### Verify Gateway Reachability
```
! From test device:
ping 151.110.239.254 -t         ! VLAN 10 gateway
ping 10.253.0.1 -t              ! VLAN 555 gateway

! Expect: Brief interruption, then continuous replies
```

### Validation
```
! On 0101a:
show hsrp brief
! All VLANs: Active (110)

show interface vlan 10 | include protocol
! All SVIs: up/up

show ip interface brief | include Vlan
! All SVIs: up/up with correct IPs

show arp summary
! ARP entries populating
```

**Checklist:**
- [ ] All SVIs: up/up on both cores
- [ ] HSRP: 0101a Active (110), 0101b Standby (100)
- [ ] Gateway pings successful
- [ ] Applications responding
- [ ] No error logs

**Status:** L3 CUTOVER COMPLETE ✅

---

## Step 3.6: Verify Static Routes

**Objective:** Confirm 174 static routes to firewall are active

### Validation
```
! On both cores:
show ip route static | count
! Expected: 174 routes

show ip route 151.110.0.0 255.255.0.0 longer-prefixes
! Verify sample routes to firewall (151.110.239.1)

ping 151.110.239.1 source loopback0
! Should succeed
```

**Checklist:**
- [ ] 174 static routes present on both cores
- [ ] Routes point to 151.110.239.1
- [ ] Firewall reachable

---

## Step 3.7: Move SECONDARY Internet Link

**Current:** 3850 Te2/0/13 ↔ NLEACEAMS0002R (VLAN 3)
**Target:** 0101b Eth1/2 ↔ NLEACEAMS0002R (VLAN 3)
**Risk:** LOW - Primary on 0101a already operational

### Procedure
```
! On 3850:
configure terminal
interface TenGigabitEthernet2/0/13
  shutdown
end

! Move cable to 0101b Eth1/2
```

### Validation
```
! On 0101b:
show interface ethernet 1/2 | include protocol
! Expected: up/up
```

**Checklist:**
- [ ] 0101b Eth1/2: up/up
- [ ] Both internet links operational

---

## Step 3.8: Move SECONDARY AVPN Link

**Current:** 3850 Te2/0/10 (trunk) ↔ NLEACOAMS0012H
**Target:** 0101b Eth1/1 (trunk) ↔ NLEACOAMS0012H
**VLANs:** 552-553, 560, 562, 620-634
**OSPF:** VLANs 552, 553
**Risk:** MEDIUM - 10-20 seconds OSPF reconvergence

### Procedure
```
! On 3850:
configure terminal
interface TenGigabitEthernet2/0/10
  shutdown
end

! Move trunk to 0101b Eth1/1
```

### Monitor OSPF
```
! On 0101b:
watch show ip ospf neighbor
! Expected: Both neighbors reach FULL state

show ip ospf neighbor
Neighbor ID     State    Interface
10.253.9.201    FULL/    Vlan552
10.253.9.205    FULL/    Vlan553
```

**Total OSPF:** 4 adjacencies (2 per core) ✅

**Checklist:**
- [ ] OSPF neighbors 10.253.9.201, 10.253.9.205: FULL
- [ ] BFD sessions up
- [ ] Total OSPF: 4 neighbors (2 per core)

---

## Step 3.9: Move SECONDARY SD-WAN Router - SDW2

**Objective:** Move all SDW2 connections to new cores

### SDW2 Connections Target

| Connection | Target | Details |
|------------|---------|---------|
| DIA-1 | 0101a Eth1/4 | VLAN 3, 6Gbps |
| DIA-2 | 0101b Eth1/4 | VLAN 3, 6Gbps |
| Transport | 0101b Eth1/5 | VLAN 630 |
| Service Po2 | vPC 2 (Eth1/10) | VLANs 631-633, BGP VLAN 632 |
| B2B MPLS | 0101b Eth1/14 | VLAN 634 |
| Management | 0102b Eth1/9 | VLAN 10, 1G |

### Procedure
Follow same pattern as Step 3.4 for SDW1:
1. Migrate DIA circuits
2. Migrate Service LANs as vPC
3. Monitor BGP formation
4. Complete remaining connections

### Monitor BGP Formation
```
! On 0101a:
show ip bgp summary | include 10.253.239.46
Neighbor        AS    State    PfxRcd
10.253.239.46 65520  Estab    692
```

**Total BGP:** 2 neighbors, 1384 prefixes ✅

**Checklist:**
- [ ] DIA circuits: Both operational (12Gbps total)
- [ ] BGP neighbor 10.253.239.46: Established, 692 prefixes
- [ ] BFD to BGP neighbor: UP
- [ ] vPC 2: Operational
- [ ] Total BGP prefixes: 1384

---

## Step 3.10: Shutdown Old 3850 SVIs

**Objective:** Disable all SVIs on old 3850 to prevent routing conflicts

### Procedure
```
! On 3850:
configure terminal
interface range vlan 10, vlan 61-63, vlan 163, vlan 555
  shutdown
interface range vlan 550-553, vlan 560, vlan 562
  shutdown
interface range vlan 574, vlan 591
  shutdown
interface range vlan 1502-1504
  shutdown
interface range vlan 620-624, vlan 630-634
  shutdown
end
copy running-config startup-config
```

### Validation
```
show ip interface brief | include Vlan
! All SVIs: administratively down

show ip route summary
! Minimal routes (only connected/default)
```

**Checklist:**
- [ ] All 3850 SVIs: shutdown
- [ ] No routing conflicts
- [ ] Applications remain functional

---

## Step 3.11: Comprehensive L3 Validation

**Objective:** Verify complete L3 migration success

### Routing Protocols
```
! On 0101a and 0101b:
show ip ospf neighbor
! Expected: 2 neighbors per core (4 total)

show ip bgp summary
! On 0101a: 2 BGP neighbors (SDW1 + SDW2), 1384 prefixes
! On 0101b: No BGP (all sessions on 0101a)

show bfd neighbors
! Expected: 6 BFD sessions total (4 OSPF + 2 BGP)
```

### High Availability
```
show hsrp brief
! 0101a: Active (110)
! 0101b: Standby (100)

show vpc
! All 3 domains operational
```

### Routing Table Comparison
```
show ip route summary
! Compare against baseline:
! - Static: 174
! - OSPF: (AVPN routes)
! - BGP: ~1384
! - Connected/Local: (all SVIs)
```

### Application Testing
Test critical applications:
- [ ] Internal connectivity (ping gateways)
- [ ] Internet access
- [ ] AVPN connectivity
- [ ] SD-WAN connectivity
- [ ] DNS resolution
- [ ] Application access

**Validation Checklist:**
- [ ] OSPF: 4 neighbors (2 per core)
- [ ] BGP: 2 neighbors, 1384 prefixes
- [ ] BFD: 6 sessions up
- [ ] HSRP: 0101a Active, 0101b Standby
- [ ] vPC: All 3 domains operational
- [ ] Static routes: 174
- [ ] All applications functional
- [ ] No critical errors

**Status:** Comprehensive L3 validation complete ✅

---

## Step 3.12: Promote New Cores to STP Root

**Objective:** Make new cores STP root bridge

**Current:** Old 3850 is root (priority 8192)
**Target:** 0101a primary root (priority 4096), 0101b secondary root (priority 8192)
**Risk:** LOW - 1-2 seconds reconvergence

**Note:** Using priority 4096 (not 8192) ensures 0101a definitively wins root election

### Set New STP Priorities

**On 0101a:**
```
configure terminal
spanning-tree vlan 1-3967 priority 4096
end
copy running-config startup-config
```

**On 0101b:**
```
configure terminal
spanning-tree vlan 1-3967 priority 8192
end
copy running-config startup-config
```

**Wait 15-30 seconds for convergence**

### Demote Old 3850
```
! On 3850:
configure terminal
spanning-tree vlan 1-4094 priority 32768
end
copy running-config startup-config
```

### Validation
```
! On 0101a:
show spanning-tree summary
! Expected: This bridge is the root

show spanning-tree vlan 10
! Priority: 4096, This bridge is the root

! On 0101b:
show spanning-tree vlan 10
! Root ID Priority: 4096 (points to 0101a)
! Bridge ID Priority: 8192

! On 3850:
show spanning-tree vlan 10
! Root ID Priority: 4096 (points to 0101a)
! Bridge ID Priority: 32768 (demoted)
```

**STP Priority Hierarchy:**
- 4096: 0101a (primary root) ✅
- 8192: 0101b (secondary root) ✅
- 16384: Access cores (0101a/b initial - now changed)
- 24576: Access primary (0102a, 0103a)
- 28672: Access secondary (0102b, 0103b)
- 32768: Old 3850 (demoted) ✅

**Checklist:**
- [ ] 0101a: Priority 4096, root bridge
- [ ] 0101b: Priority 8192, secondary root
- [ ] 3850: Priority 32768, demoted
- [ ] All ports stable, forwarding
- [ ] No STP errors

**Status:** STP root promoted to new cores ✅

---

## Step 3.13: Final Validation & Documentation

### Final System Check
```
! On both cores:
show logging | include % | tail 50
! Review for any errors

show processes cpu sorted
! CPU normal

show environment all
! Temperature/power normal
```

### Document Final State
Record final metrics:
- [ ] All WAN uplinks operational on new cores
- [ ] All routing protocols stable
- [ ] HSRP Active/Standby verified
- [ ] STP topology correct
- [ ] Applications functional
- [ ] NOC confirms normal operations

### Success Criteria Met
- [x] All WAN uplinks migrated
- [x] HSRP gateways active
- [x] Routing protocols operational
- [x] STP root promoted
- [x] Applications functional
- [x] No critical errors

**Status:** Phase 3 L3 Migration COMPLETE ✅

---

## Step 3.14: Maintenance Window Closure

### Final Tasks
1. Update change ticket with results
2. Notify stakeholders of successful migration
3. Schedule post-migration review (24-48 hours)
4. Keep rollback plan ready for 72 hours

### Post-Migration Monitoring
Monitor for next 72 hours:
- Routing protocol stability
- HSRP failover testing
- Interface errors
- System logs
- Application performance

### Rollback Window
**Rollback possible:** Next 72 hours
**After 72 hours:** Consider migration permanent

---

## Emergency Rollback Procedure

### If Critical Issue Occurs

**Before Step 3.5 (HSRP activation):**
- Reverse cable moves in opposite order
- No configuration changes needed

**After Step 3.5 (HSRP active):**
1. Shutdown all SVIs on new cores
2. No shutdown SVIs on old 3850
3. Move cables back to 3850 in reverse order
4. Verify all services restored

**Full Rollback Steps:**
```
! On 0101a/0101b:
configure terminal
interface range vlan 10, vlan 61-63, vlan 163, vlan 555, vlan 550-553
  shutdown
! Shutdown all other SVIs
end

! On 3850:
configure terminal
interface range vlan 10, vlan 61-63, vlan 163, vlan 555, vlan 550-553
  no shutdown
! No shutdown all other SVIs
end

! Move cables back in reverse order:
! - Secondary SD-WAN (SDW2) back to 3850
! - Secondary AVPN back to 3850 Te2/0/10
! - Secondary Internet back to 3850 Te2/0/13
! - Primary SD-WAN (SDW1) back to 3850
! - Primary AVPN back to 3850 Te1/0/10
! - Primary Internet back to 3850 Te1/0/13

! Verify services restored:
show ip ospf neighbor    ! 4 neighbors
show ip bgp summary      ! 2 neighbors
show hsrp brief          ! All Active
```

---

## Quick Reference - Port Mappings

### Internet Uplinks
- **Primary:** 3850 Te1/0/13 → 0101a Eth1/2 (VLAN 3)
- **Secondary:** 3850 Te2/0/13 → 0101b Eth1/2 (VLAN 3)

### AVPN Uplinks
- **Primary:** 3850 Te1/0/10 → 0101a Eth1/1 (trunk: 550-551, 553, 560, 562, 620-634)
- **Secondary:** 3850 Te2/0/10 → 0101b Eth1/1 (trunk: 552-553, 560, 562, 620-634)

### SD-WAN Routers
**SDW1:**
- DIA-1: 0101a Eth1/3 (VLAN 3)
- DIA-2: 0101b Eth1/3 (VLAN 3)
- Service: vPC 1 (0101a Eth1/9, 0101b Eth1/9) - VLANs 621-623, BGP 622
- Management: 0102a Eth1/9 (VLAN 10)

**SDW2:**
- DIA-1: 0101a Eth1/4 (VLAN 3)
- DIA-2: 0101b Eth1/4 (VLAN 3)
- Service: vPC 2 (0101a Eth1/10, 0101b Eth1/10) - VLANs 631-633, BGP 632
- Management: 0102b Eth1/9 (VLAN 10)

### Expected Metrics
- **OSPF:** 4 neighbors (2 per core)
- **BGP:** 2 neighbors (both on 0101a), 1384 total prefixes
- **BFD:** 6 sessions (4 OSPF + 2 BGP)
- **HSRP:** 0101a Active (110), 0101b Standby (100)
- **Static Routes:** 174 (to firewall 151.110.239.1)
- **STP:** 0101a root (4096), 0101b secondary (8192)

---

**END OF RUNBOOK**
