# Phase 2: Physical Installation & L2 Interconnect

**Risk Level:** LOW - No production impact
**Impact:** None - Only adding new infrastructure

---

## Objectives

1. Install all 6 Nexus switches in racks
2. Establish management connectivity
3. Validate vPC formation
4. Build Layer 2 trunk between old and new environments
5. Verify STP topology

---

## Step 2.1: Physical Installation

**Installation Procedure:**

1. **Mount switches in designated positions:**
   - Core: AMIDCnsm0101a, AMIDCnsm0101b (Rack ___, U ___)
   - Fiber Access: AMIDCnsm0103a, AMIDCnsm0103b (Rack ___,U ___)
   - Copper Access: AMIDCnsm0102a, AMIDCnsm0102b (Rack ___, U ___)

2. **Install power supplies:**
   - Each switch: Dual redundant PSUs
   - Connect to A+B power circuits
   - Verify power LEDs green

3. **Console connectivity:**
   - Connect all 6 console ports to console server
   - Label console ports clearly
   - Test console access from management station

**Validation:**
```
! From management workstation:
ssh console-server
! Connect to each switch console port
! Verify boot process completes
! Check NX-OS version
show version
```

---

## Step 2.2: Management Network (30 minutes)

### Connect Management Interfaces

**Procedure:**
1. Connect mgmt0 on all switches to management VLAN 555
2. Verify IP reachability

**Validation:**
```
! From management workstation:
ping 10.253.0.2  ! 0101a
ping 10.253.0.3  ! 0101b
ping 10.253.0.4  ! 0103a
ping 10.253.0.5  ! 0103b
ping 10.253.0.6  ! 0102a
ping 10.253.0.7  ! 0102b

! SSH to each switch:
ssh admin@10.253.0.2
! Verify TACACS+ authentication working
```

**Load Configurations:**
```
! Option 1: TFTP/SCP copy
copy tftp://10.253.0.x/0101a-config.txt running-config

! Option 2: Paste via console (for smaller configs)
! Copy/paste prepared configs

! Verify and save:
show running-config
copy running-config startup-config
```

---

## Step 2.3: vPC Peer Link Formation (1 hour)

### Core Layer vPC (Domain 101)

**Physical Cabling:**
- Connect 100G QSFP28 cables:
  - 0101a Eth1/47 ↔ 0101b Eth1/47
  - 0101a Eth1/48 ↔ 0101b Eth1/48

**Verify Port Status:**
```
! On both 0101a and 0101b:
show interface ethernet 1/47
show interface ethernet 1/48

! Expected: up/up
```

**Verify Port-Channel Formation:**
```
show port-channel summary

! Expected output:
! Po100    LACP    Eth1/47(P), Eth1/48(P)

show interface port-channel 100
! State: up
```

**Verify vPC Status:**
```
show vpc

! Expected output:
! vPC domain id                     : 101
! Peer status                       : peer adjacency formed ok
! vPC keep-alive status             : peer is alive
! Configuration consistency status  : success
! Per-vlan consistency status       : success
! vPC role                          : primary (on 0101a) / secondary (on 0101b)
! Number of vPCs configured         : 0 (will increase as we add vPC interfaces)
! Peer link status                  : up

show vpc peer-keepalive

! Expected:
! status: UP
! Destination: 10.253.0.3 (from 0101a) / 10.253.0.2 (from 0101b)
! Source: 10.253.0.2 (from 0101a) / 10.253.0.3 (from 0101b)
```

**Common Issues:**

| Issue | Symptom | Resolution |
|-------|---------|------------|
| Peer-keepalive down | Peer status: down | Check mgmt IP reachability |
| Peer link down | Peer link: down | Check physical cables, interface status |
| Consistency failure | Config mismatch | Review configs on both switches, ensure identical vPC settings |

### Fiber Access vPC (Domain 103)

**Physical Cabling:**
- Connect 100G QSFP28 cables:
  - 0103a Eth1/53 ↔ 0103b Eth1/53
  - 0103a Eth1/54 ↔ 0103b Eth1/54

**Validation:**
```
! On both 0103a and 0103b:
show vpc
! Domain: 103
! Peer status: peer adjacency formed ok

show port-channel summary
! Po100 up
```

### Copper Access vPC (Domain 102)

**Physical Cabling:**
- Connect 100G QSFP28 cables:
  - 0102a Eth1/53 ↔ 0102b Eth1/53
  - 0102a Eth1/54 ↔ 0102b Eth1/54

**Validation:**
```
! On both 0102a and 0102b:
show vpc
! Domain: 102
! Peer status: peer adjacency formed ok

show port-channel summary
! Po100 up
```

**Validation Checklist:**
- [ ] vPC domain 101: Peer adjacency formed
- [ ] vPC domain 102: Peer adjacency formed
- [ ] vPC domain 103: Peer adjacency formed
- [ ] All peer-links up (Po100 on each pair)
- [ ] Peer-keepalive alive on all domains
- [ ] No consistency errors on any domain

---

## Step 2.4: Inter-Layer Connectivity (30 minutes)

### Core to Fiber Access

**Physical Cabling:**

| Source | Interface | Destination | Interface | Cable Type |
|--------|-----------|-------------|-----------|------------|
| 0101a | Eth1/49 | 0103a | Eth1/49 | Fiber/DAC |
| 0101a | Eth1/50 | 0103b | Eth1/49 | Fiber/DAC |
| 0101b | Eth1/49 | 0103a | Eth1/50 | Fiber/DAC |
| 0101b | Eth1/50 | 0103b | Eth1/50 | Fiber/DAC |

**Validation:**
```
! On cores (0101a/0101b):
show port-channel summary | include Po103

! Expected: Po103(SU) - 4 members (P)

show vpc 103

! Expected:
! vPC status: up
! Consistency: success

! On fiber access (0103a/0103b):
show port-channel summary | include Po103
show vpc 103
```

### Core to Copper Access

**Physical Cabling:**

| Source | Interface | Destination | Interface | Cable Type |
|--------|-----------|-------------|-----------|------------|
| 0101a | Eth1/53 | 0102a | Eth1/49 | Fiber/DAC |
| 0101a | Eth1/54 | 0102b | Eth1/49 | Fiber/DAC |
| 0101b | Eth1/53 | 0102a | Eth1/50 | Fiber/DAC |
| 0101b | Eth1/54 | 0102b | Eth1/50 | Fiber/DAC |

**Validation:**
```
! On cores (0101a/0101b):
show port-channel summary | include Po102

! Expected: Po102(SU) - 4 members (P)

show vpc 102

! On copper access (0102a/0102b):
show port-channel summary | include Po102
show vpc 102
```

**Validation Checklist:**
- [ ] Po102: 4 members up (core ↔ copper access)
- [ ] Po103: 4 members up (core ↔ fiber access)
- [ ] vPC 102 operational
- [ ] vPC 103 operational
- [ ] No port-channel suspended or down

---

## Step 2.5: Build L2 Trunk to Old 3850 (1 hour)

### Configuration on Old 3850 Stack

**Connect to 3850:**
```
ssh admin@<3850-management-IP>
enable
configure terminal
```

**Create Port-Channel 200:**
```
interface Port-channel200
  description L2-TRUNK-TO-NEW-NEXUS-ENVIRONMENT
  switchport mode trunk
  switchport trunk allowed vlan all
  no shutdown
exit
```

**Add Member Interfaces:**
```
interface GigabitEthernet3/0/1
  description TO-NEW-0102a-Eth1/21-L2-TRUNK
  switchport mode trunk
  switchport trunk allowed vlan all
  channel-group 200 mode active
  no shutdown
  speed 1000
  duplex full

interface GigabitEthernet3/0/2
  description TO-NEW-0102b-Eth1/21-L2-TRUNK
  switchport mode trunk
  switchport trunk allowed vlan all
  channel-group 200 mode active
  no shutdown
  speed 1000
  duplex full

interface GigabitEthernet4/0/1
  description TO-NEW-0102a-Eth1/22-L2-TRUNK
  switchport mode trunk
  switchport trunk allowed vlan all
  channel-group 200 mode active
  no shutdown
  speed 1000
  duplex full

interface GigabitEthernet4/0/2
  description TO-NEW-0102b-Eth1/22-L2-TRUNK
  switchport mode trunk
  switchport trunk allowed vlan all
  channel-group 200 mode active
  no shutdown
  speed 1000
  duplex full

exit
copy running-config startup-config
```

### Physical Cable Connections

**Connect 4 cables:**
1. 3850 Gi3/0/1 ↔ 0102a Eth1/21 (Cat6 copper, Label: "L2-TRUNK-1")
2. 3850 Gi3/0/2 ↔ 0102b Eth1/21 (Cat6 copper, Label: "L2-TRUNK-2")
3. 3850 Gi4/0/1 ↔ 0102a Eth1/22 (Cat6 copper, Label: "L2-TRUNK-3")
4. 3850 Gi4/0/2 ↔ 0102b Eth1/22 (Cat6 copper, Label: "L2-TRUNK-4")

**Port Selection:**
- Consecutive ports (Eth1/21-22) on both Nexus switches
- Matching port numbers for symmetrical design
- All ports within 1-48 copper range
- All currently shutdown/unused (verified)

### Validation

**On Old 3850:**
```
show etherchannel summary | include Po200

! Expected output:
! 200    Po200(SU)         LACP      Gi3/0/1(P)    Gi3/0/2(P)
!                                    Gi4/0/1(P)    Gi4/0/2(P)

show interface port-channel 200

! Expected:
! Port-channel200 is up, line protocol is up

show interface port-channel 200 | include rate

! Note traffic rates (should be minimal initially)

show spanning-tree interface port-channel 200

! Verify: Forwarding state
```

**On New Copper Access (0102a/0102b):**
```
show port-channel summary | include Po200

! Expected:
! Po200(SU) - Eth1/21(P), Eth1/22(P)  ! (vPC)

show vpc 200

! Expected:
! vPC status: up
! Consistency: success
! vPC mode: active

show interface port-channel 200
show interface port-channel 200 | include rate
```

**Topology Verification:**
```
Old 3850 Stack (Po200)
  ├─ Gi3/0/1 ──────┐
  ├─ Gi3/0/2 ──────┼──> [L2 Trunk - ALL VLANs]
  ├─ Gi4/0/1 ──────┤
  └─ Gi4/0/2 ──────┘
                    │
         ┌──────────┴──────────┐
         │                     │
    0102a Eth1/21-22      0102b Eth1/21-22
         │                     │
         └────[vPC 200]────────┘
                  │
         (via Po103/Po104)
                  │
         ┌────────┴────────┐
      0101a            0101b
    (New Cores)
```

---

## Step 2.6: Spanning Tree Validation (30 minutes)

### Verify STP Root Bridge

**IMPORTANT:** New core switches are pre-configured with **spanning-tree vlan 1-3967 priority 16384**. This ensures the old 3850 stack (priority 8192) remains as STP root throughout Phase 2 and Phase 3. The new cores will only become STP root in **Phase 3 Step 3.12** after gateway migration is complete.

**On Old 3850:**
```
show spanning-tree summary

! Expected output:
! Root ID:
!   Priority    8192
!   Address     xxxx.xxxx.xxxx
!   This bridge is the root

show spanning-tree root

! All VLANs should show:
! Root ID: 8192 (this bridge)
```

**On New Switches:**
```
! On cores (0101a/0101b):
show spanning-tree summary

! Expected:
! Root ID: 8192 (3850 MAC address)
! Bridge priority: 16384 (secondary root - configured in all core configs)

! Verify local priority configured:
show running-config | include "spanning-tree vlan"
! Expected: spanning-tree vlan 1-3967 priority 16384

show spanning-tree root

! Should show old 3850 as root
! Cost to root via Po200 (L2 trunk)

! On access layers (0102a/b, 0103a/b):
show spanning-tree summary

! Expected:
! Root ID: 8192 (3850 MAC address)
! Bridge priority: 24576 (0102a/0103a) or 28672 (0102b/0103b)

! Verify local priority configured:
show running-config | include "spanning-tree vlan"
! Expected: spanning-tree vlan 1-3967 priority 24576 (primary access)
! Expected: spanning-tree vlan 1-3967 priority 28672 (secondary access)

show spanning-tree root

! Should show old 3850 as root
! Cost to root via uplink port-channels
```

### Verify Port States

**On Old 3850:**
```
show spanning-tree interface port-channel 200

! Port 200 (Port-channel200) of VLAN0010 is forwarding

show spanning-tree interface port-channel 200 detail

! Verify:
! - Port role: Designated (root bridge)
! - Port state: Forwarding
```

**On New Copper Access:**
```
show spanning-tree interface port-channel 200

! Should be Forwarding
! Role: Root (pointing toward old 3850)

show spanning-tree interface port-channel 102

! Uplink to cores: Forwarding
```

**On New Cores:**
```
show spanning-tree interface port-channel 102

! Downlink to copper access: Forwarding

show spanning-tree interface port-channel 103

! Downlink to fiber access: Forwarding
```

### Check for STP Issues

```
! On all switches:
show spanning-tree inconsistentports

! Expected: None

show logging | include LOOP
show logging | include TCN
show logging | include STP

! Should not show any loops or excessive topology changes
```

**STP Validation Checklist:**
- [ ] Old 3850: Priority 8192, THIS BRIDGE IS ROOT
- [ ] New cores (0101a/b): Priority 16384, sees 3850 as root
- [ ] Access primary (0102a/0103a): Priority 24576, sees 3850 as root
- [ ] Access secondary (0102b/0103b): Priority 28672, sees 3850 as root
- [ ] Po200: Forwarding on both sides (L2 trunk to 3850)
- [ ] All uplink port-channels: Forwarding
- [ ] All inter-switch port-channels: Forwarding
- [ ] No STP loops detected
- [ ] No blocked ports (except by design)
- [ ] No excessive TCN (topology change notifications)

---

## Step 2.7: End-to-End L2 Verification (30 minutes)

### VLAN Propagation Test

**On Old 3850:**
```
show vlan brief | count

! Note total VLAN count: _____
```

**On New Cores:**
```
show vlan brief | count

! Should match or be close to 3850 count
```

**Spot Check Specific VLANs:**
```
! On all switches:
show vlan id 10
show vlan id 555
show vlan id 622

! Verify VLANs exist and active
```

### MAC Address Learning

**On Old 3850:**
```
show mac address-table dynamic | include Po200

! Should show some MACs learned via Po200 (L2 trunk)
```

**On New Cores:**
```
show mac address-table dynamic | count

! Should start seeing MACs (initially few, will grow over time)

show mac address-table dynamic vlan 555

! Management VLAN should show some entries
```

### L2 Connectivity Test (Optional)

**If test device available:**
1. Connect test laptop to new access layer
2. Configure IP in test VLAN (e.g., VLAN 555)
3. Ping current gateway (still on old 3850)
4. Should work via L2 trunk

**Example:**
```
Test device: IP 10.253.0.100/25, Gateway 10.253.0.1 (on 3850)
Ping 10.253.0.1  → Should succeed
Trace 10.253.0.1 → Should show L2 path via new switches
```

---

## Step 2.8: Final Pre-Maintenance Validation (1 hour)

### Configuration Backups

**On all switches (old and new):**
```
! On 3850:
show running-config > flash:backup-3850-pre-phase3-<date>.cfg
copy running-config tftp://10.253.0.x/backups/3850-<date>.cfg

! On new switches:
copy running-config startup-config
copy running-config tftp://10.253.0.x/backups/<hostname>-<date>.cfg
```

### System Health Checks

**On all new switches:**
```
show version
show module
show environment
show processes cpu
show system resources
show logging | include ERR
show logging | include CRIT
```

**Expected Results:**
- NX-OS version: Correct/approved version
- All modules: Online
- Temperatures: Normal range
- CPU: < 20% (idle)
- Memory: < 50% used
- No critical errors in logs

### Network Topology Confirmation

**Validate Current State:**

```
OLD ENVIRONMENT (3850):
- L3 Active: YES (all routing, gateways)
- L2 Active: YES (switching)
- STP Root: YES (priority 8192)
- WAN Uplinks: YES (all connected)

NEW ENVIRONMENT (Nexus):
- L3 Active: NO (SVIs configured but routing not active)
- L2 Active: YES (switching, trunking)
- STP Priorities:
  - Cores (0101a/b): 16384 (secondary root)
  - Access primary (0102a/0103a): 24576 (tertiary)
  - Access secondary (0102b/0103b): 28672 (quaternary)
- WAN Uplinks: NO (not connected yet)

L2 INTERCONNECT:
- Po200: UP (8Gbps, 4x 1G)
- All VLANs: Trunked
- Status: Operational
```

### Go/No-Go Checklist

**Hardware:**
- [ ] All 6 switches installed and powered
- [ ] All console access working
- [ ] All management IPs reachable

**vPC:**
- [ ] Domain 101: Operational (cores)
- [ ] Domain 102: Operational (copper access)
- [ ] Domain 103: Operational (fiber access)
- [ ] All peer-links up
- [ ] All peer-keepalives alive

**Inter-Connectivity:**
- [ ] Po102: Up (core ↔ copper access)
- [ ] Po103: Up (core ↔ fiber access)
- [ ] Po200: Up (old 3850 ↔ new environment)

**Spanning Tree:**
- [ ] Old 3850: Root bridge (priority 8192)
- [ ] New cores: Secondary root (priority 16384)
- [ ] Access primary: Tertiary (priority 24576)
- [ ] Access secondary: Quaternary (priority 28672)
- [ ] All trunks: Forwarding
- [ ] No STP loops
- [ ] Priority hierarchy verified: 8192 < 16384 < 24576 < 28672

**Configurations:**
- [ ] All configs loaded and saved
- [ ] Backups taken and stored
- [ ] HSRP configured (waiting for activation)
- [ ] OSPF/BGP configured (waiting for activation)

**Team Readiness:**
- [ ] All engineers briefed
- [ ] Roles assigned
- [ ] Maintenance window confirmed
- [ ] Emergency contacts ready
- [ ] Rollback plan reviewed

**Approvals:**
- [ ] Change request approved
- [ ] Maintenance window scheduled
- [ ] Stakeholders notified
- [ ] Management sign-off

---

**PHASE 2 COMPLETE - Ready for Phase 3 (Saturday Maintenance Window)**

**Current Status:**
- New infrastructure online and operational (L2 only)
- Layer 2 trunk established to old environment
- All systems ready for L3 migration
- Zero production impact to date

**Next Phase:**
- Phase 3: L3 Migration (Saturday evening, 6-8 hours)
- Move WAN uplinks, activate routing, cutover gateways
