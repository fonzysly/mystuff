# Phase 3: L3 Migration - Part 2 (Steps 3.7-3.14)

## Step 3.7: Move SECONDARY Internet Link (9:15 PM - 9:30 PM)

**Objective:** Move secondary internet uplink from 3850 to new core 0101b

**Current:** 3850 Te?/? ↔ NLEACEAMS0002R (VLAN 3)
**Target:** 0101b Eth1/2 ↔ NLEACEAMS0002R (VLAN 3)

**Risk:** MINIMAL - Primary path active on 0101a, full redundancy maintained

### Pre-Checks (9:15 PM)

**Identify current secondary internet port:**
```
! On 3850:
show interface status | include NLEACEAMS0002R
show running-config interface TenGigabitEthernet<X>/<Y>

→ Secondary internet port: Te____
```

**Verify new core ready:**
```
! On 0101b:
show running-config interface ethernet 1/2
show interface ethernet 1/2 status

→ Should be configured, access VLAN 3
```

### Physical Cable Move (9:18 PM)

**Announce:** "Moving secondary internet link. Primary path active. No expected downtime."

**Procedure:**
```
! On 3850:
configure terminal
interface TenGigabitEthernet<X>/<Y>
  shutdown
end
```

⏱️ **Start Timer**

1. Disconnect cable from 3850 Te?/?
2. Connect cable to 0101b Eth1/2
3. Interface should auto-enable

**Elapsed Time:** ______ seconds

### Validation (9:22 PM)

**On 0101b:**
```
show interface ethernet 1/2 | include protocol
→ Expected: "line protocol is up"

show interface ethernet 1/2 switchport
→ VLAN 3 access mode

show mac address-table interface ethernet 1/2
→ Should see upstream router MAC

show interface ethernet 1/2 | include rate
→ Should see traffic (in/out)
```

**Test Redundancy:**
```
! From test device on VLAN 3:
Test internet connectivity (using both paths)
```

### Validation Checklist

- [ ] 0101b Eth1/2: up/up ⏱️ Time: ______ seconds
- [ ] VLAN 3 active on 0101b
- [ ] Both internet links operational (0101a + 0101b)
- [ ] Internet connectivity validated
- [ ] No errors in logs

**Status Update:** "Secondary internet link migrated to core 0101b. Dual internet paths operational. ✅"

---

## Step 3.8: Move SECONDARY AVPN Link (9:30 PM - 10:00 PM)

**Objective:** Move AVPN router NLEACOAMS0012H from 3850 to new core 0101b

**Current:** 3850 Te2/0/10 (trunk) ↔ NLEACOAMS0012H
**Target:** 0101b Eth1/1 (trunk) ↔ NLEACOAMS0012H

**VLANs:** 550-551, 553, 560, 562, 620-634
**OSPF:** VLANs 552 (10.253.9.200/30), 553 (10.253.9.204/30)

**Risk:** MEDIUM - 10-20 seconds OSPF reconvergence expected

### Pre-Checks (9:30 PM)

**On Old 3850:**
```
show interface te2/0/10 | include protocol
show interface te2/0/10 switchport
→ Trunk, VLANs 550-553,560,562,620-634

show ip ospf neighbor

Neighbor ID     State    Interface
10.253.9.201    FULL/    Vlan552
10.253.9.205    FULL/    Vlan553
```

**On 0101b:**
```
show running-config interface ethernet 1/1
show interface ethernet 1/1 status
→ Configured, ready

show running-config interface vlan 552
show running-config interface vlan 553
→ IPs configured, OSPF enabled, awaiting neighbor

show interface loopback0
→ 10.253.9.62/32 - up
```

### Physical Cable Move (9:35 PM)

**Announce:** "Beginning AVPN secondary link migration. Expect 10-20 second OSPF convergence."

**Procedure:**
```
! On 3850:
configure terminal
interface TenGigabitEthernet2/0/10
  shutdown
end
```

⏱️ **Start Timer**

1. Disconnect trunk cable from 3850 Te2/0/10
2. Connect trunk cable to 0101b Eth1/1
3. Interface should auto-enable

### Monitor OSPF Formation (9:37 PM)

**On 0101b:**
```
! Watch interface come up:
show interface ethernet 1/1 | include protocol

! Watch VLANs activate:
show vlan brief | include 552
show vlan brief | include 553

! Watch OSPF neighbors form:
watch show ip ospf neighbor

! Expected progression:
! (empty) → INIT → 2-WAY → EXSTART → EXCHANGE → LOADING → FULL
! Typical time: 10-40 seconds
```

**Continuously monitor:**
```
show ip ospf neighbor

! Target state (after convergence):
Neighbor ID     State    Interface
10.253.9.201    FULL/    Vlan552
10.253.9.205    FULL/    Vlan553
```

**Elapsed Time to FULL:** ______ seconds

### Validation (9:45 PM)

**OSPF Status:**
```
! On 0101b:
show ip ospf neighbor detail

Neighbor 10.253.9.201 (VLAN 552):
- State: FULL
- Dead time: 00:00:3x

Neighbor 10.253.9.205 (VLAN 553):
- State: FULL
- Dead time: 00:00:3x

show ip ospf interface brief
→ VLANs 552, 553 should be up
```

**Routing Table:**
```
show ip route ospf
→ Should see routes learned from AVPN

show ip route 10.0.0.0
→ Check sample AVPN route present
```

**BFD Status:**
```
show bfd neighbors
→ Sessions to 10.253.9.201 and 10.253.9.205 should be UP
→ Interval: 300ms, min_rx: 100ms, multiplier: 3
```

**Interface Traffic:**
```
show interface vlan 552 | include rate
show interface vlan 553 | include rate
→ Should see input/output packets
```

**On Old 3850:**
```
show ip ospf neighbor
→ Should now show 0 neighbors (all migrated)
```

**Total OSPF Count:**
- 0101a: 2 neighbors (VLANs 550, 551)
- 0101b: 2 neighbors (VLANs 552, 553)
- **Total: 4 adjacencies active** ✅

### Rollback Procedure (If Needed)

```
! On 0101b:
configure terminal
interface ethernet 1/1
  shutdown
end

! Reconnect cable to 3850 Te2/0/10

! On 3850:
configure terminal
interface TenGigabitEthernet2/0/10
  no shutdown
end

! Wait for OSPF to reconverge (10-30 seconds)
show ip ospf neighbor
```

### Validation Checklist

- [ ] 0101b Eth1/1: up/up ⏱️ Time: ______ seconds
- [ ] VLANs 552, 553 active on 0101b
- [ ] OSPF neighbor 10.253.9.201 (VLAN 552): FULL
- [ ] OSPF neighbor 10.253.9.205 (VLAN 553): FULL
- [ ] Routes learned via OSPF on 0101b
- [ ] Old 3850: 0 OSPF neighbors remaining
- [ ] Total OSPF adjacencies across both cores: 4
- [ ] BFD sessions up (300ms/100ms/3)
- [ ] No OSPF errors in logs

**Status Update:** "Secondary AVPN link migrated to core 0101b. All 4 OSPF adjacencies operational. ✅"

---

## Step 3.9: Move SECONDARY SD-WAN Router - SDW2 (10:00 PM - 10:45 PM)

**Objective:** Move ALL SDW2 connections from 3850 to new cores

**⚠️ CRITICAL:** This moves final 12Gbps of DIA circuits and completes SD-WAN migration

### Current SDW2 Connections on 3850

1. **DIA Circuit 1:** Te0/0/7 ↔ 3850 (VLAN 3) - 6Gbps
2. **DIA Circuit 2:** Te0/0/1 ↔ 3850 (VLAN 3) - 6Gbps
3. **Transport VPN:** Te0/0/0 ↔ 3850 (VLAN 630)
4. **Service LAN:** Te0/0/3 + Te0/0/4 ↔ 3850 (VLANs 631-633, includes BGP VLAN 632)
5. **B2B MPLS:** Te0/0/5 ↔ 3850 (VLAN 634)
6. **Management:** Gi0/0 ↔ 3850 (VLAN 10)

### Target Configuration

**Split across cores for redundancy:**
- **DIA-1 (Te0/0/7):** 0101a Eth1/4 (VLAN 3, 6Gbps)
- **DIA-2 (Te0/0/1):** 0101b Eth1/4 (VLAN 3, 6Gbps)
- **Transport (Te0/0/0):** 0101b Eth1/6 (VLAN 630)
- **Service Po2 (Te0/0/3):** 0101a Eth1/10 (VLANs 631-633, vPC member)
- **Service Po2 (Te0/0/4):** 0101b Eth1/10 (VLANs 631-633, vPC member)
- **B2B (Te0/0/5):** 0101b Eth1/14 (VLAN 634, single-homed)
- **Management (Gi0/0):** 0102a Eth1/20 (VLAN 10, 1G copper)

### Pre-Checks (10:00 PM)

**On 3850:**
```
show interface status | include SDW2
show interface status | include Amidcnrm0102
show etherchannel summary
show ip bgp summary | include 10.253.239.46

Neighbor        AS    State    PfxRcd
10.253.239.46 65520  Estab    692
```

**On New Cores:**
```
! On 0101a:
show running-config interface ethernet 1/4
show running-config interface ethernet 1/10

! On 0101b:
show running-config interface ethernet 1/4
show running-config interface ethernet 1/6
show running-config interface ethernet 1/10
show running-config interface ethernet 1/14

! On both cores:
show running-config interface port-channel 2
show vpc 2
→ Should show "down" (not yet connected)

! On 0102a:
show running-config interface ethernet 1/20
```

### Coordinate with SD-WAN Team (10:05 PM)

**Announce:** "Beginning SDW2 migration. Expect 5-10 minute outage for SD-WAN router 2 and DIA circuits. This completes SD-WAN migration."

**Notify:**
- SD-WAN team
- NOC
- Impacted stakeholders

### Migrate DIA Circuits (10:10 PM)

**DIA Circuit 1 (Te0/0/7 → 0101a Eth1/4):**
```
! On 3850:
configure terminal
interface TenGigabitEthernet<X>/<Y>  ! Connected to SDW2 Te0/0/7
  shutdown
end
```

⏱️ **Start Timer: DIA-1**

- Disconnect: 3850 Te?/?
- Connect: 0101a Eth1/4

**DIA Circuit 2 (Te0/0/1 → 0101b Eth1/4):**
```
! On 3850:
configure terminal
interface TenGigabitEthernet<X>/<Y>  ! Connected to SDW2 Te0/0/1
  shutdown
end
```

- Disconnect: 3850 Te?/?
- Connect: 0101b Eth1/4

**Elapsed Time:** ______ seconds

### Verify DIA Circuits Up (10:15 PM)

**On 0101a:**
```
show interface ethernet 1/4 | include protocol
→ "line protocol is up"

show interface ethernet 1/4 switchport
→ Access VLAN 3

show interface ethernet 1/4 | include rate
→ Should see traffic
```

**On 0101b:**
```
show interface ethernet 1/4 | include protocol
show interface ethernet 1/4 switchport
show interface ethernet 1/4 | include rate
```

### Migrate Transport and B2B (10:18 PM)

**Transport VPN (Te0/0/0 → 0101b Eth1/6):**
```
! On 3850:
configure terminal
interface TenGigabitEthernet<X>/<Y>  ! Connected to SDW2 Te0/0/0
  shutdown
end
```

- Disconnect: 3850 Te?/?
- Connect: 0101b Eth1/6 (VLAN 630)

**B2B MPLS (Te0/0/5 → 0101b Eth1/14):**
```
! On 3850:
configure terminal
interface TenGigabitEthernet<X>/<Y>  ! Connected to SDW2 Te0/0/5
  shutdown
end
```

- Disconnect: 3850 Te?/?
- Connect: 0101b Eth1/14 (VLAN 634)

### Migrate Service LANs as vPC (10:22 PM)

**⚠️ CRITICAL: These carry BGP session on VLAN 632**

**Identify current ports on 3850:**
```
! On 3850:
show interface status | include SDW2
→ Note ports connected to SDW2 Te0/0/3 and Te0/0/4
```

**Shutdown on 3850:**
```
! On 3850:
configure terminal
interface TenGigabitEthernet<X>/<Y>  ! SDW2 Te0/0/3
  shutdown
interface TenGigabitEthernet<A>/<B>  ! SDW2 Te0/0/4
  shutdown
end
```

**Connect to new cores:**
- SDW2 Te0/0/3 → 0101a Eth1/10 (Po2 member, VLANs 631-633)
- SDW2 Te0/0/4 → 0101b Eth1/10 (Po2 member, VLANs 631-633)

### Verify Port-Channel Forms (10:28 PM)

**On both 0101a and 0101b:**
```
show port-channel summary | include Po2

! Expected:
! 2    Po2(SU) - Eth1/10(P)  ! (vPC)

show vpc 2

→ vPC status: up
→ Consistency check: success
→ Active vlans: 631-633
```

### Monitor BGP Session Formation (10:32 PM)

**⚠️ CRITICAL MOMENT - BGP to SDW2 should establish**

**On 0101a:**
```
! Watch BGP neighbor state:
watch show ip bgp summary

! Expected progression:
! Idle → Connect → OpenSent → OpenConfirm → Established
! Typical time: 30-90 seconds
```

**Target state:**
```
show ip bgp summary

Neighbor        AS    State    PfxRcd  Up/Down
10.253.238.46 65520  Estab    692     00:XX:XX  (SDW1 - existing)
10.253.239.46 65520  Estab    692     00:00:xx  (SDW2 - new)

show ip bgp neighbors 10.253.239.46 | include Update-source
→ Update source: Vlan632 (CRITICAL - must match config)
```

**Elapsed Time to Established:** ______ seconds

### Migrate Management Port (10:38 PM)

**Management (Gi0/0 → 0102a Eth1/20):**
```
! On 3850:
configure terminal
interface GigabitEthernet<X>/<Y>  ! Connected to SDW2 Gi0/0
  shutdown
end
```

- Disconnect: 3850 Gi?/?
- Connect: 0102a Eth1/20 (VLAN 10, 1G copper)

**Verify on 0102a:**
```
show interface ethernet 1/20 | include protocol
show interface ethernet 1/20 switchport
→ Access VLAN 10
```

### Validation (10:40 PM)

**Interface Status:**
```
! On 0101a:
show interface ethernet 1/4 | include rate  ! DIA-1
show port-channel 2 brief                    ! Service LANs

! On 0101b:
show interface ethernet 1/4 | include rate  ! DIA-2
show interface ethernet 1/6 | include rate  ! Transport
show interface ethernet 1/14 | include rate ! B2B
show port-channel 2 brief                    ! Service LANs

! On 0102a:
show interface ethernet 1/20 | include rate  ! Management

→ All should show traffic flowing
```

**Port-Channel Status:**
```
! On both cores:
show port-channel summary | include Po2
show vpc 2

→ Po2 up, vPC operational, VLANs 631-633 active
```

**BGP Status:**
```
! On 0101a:
show ip bgp summary

Neighbor 10.253.238.46:
- State: Established
- PfxRcd: 692
- Update-source: Vlan622

Neighbor 10.253.239.46:
- State: Established
- PfxRcd: 692
- Update-source: Vlan632

show ip route bgp | count
→ Should show ~1384 BGP routes learned (692 × 2)

show ip bgp neighbors 10.253.239.46 | include state
→ BGP state = Established
```

**BFD Status:**
```
show bfd neighbors | include 10.253.239.46

→ Session up, interval 300ms, multiplier 3
```

**DIA Circuit Validation:**
```
! Test internet via DIA circuits:
! From device on VLAN 3 or via SDW2:
ping 8.8.8.8
traceroute 8.8.8.8

→ Should succeed via DIA circuits
```

**Complete SD-WAN Summary:**
```
! On 0101a:
show ip bgp summary

→ Should show 2 neighbors (SDW1 + SDW2), both Established
→ Total prefixes: ~1384
```

**On Old 3850:**
```
show ip bgp summary

→ Should show 0 BGP neighbors (all migrated)
```

### Rollback Procedure (If Needed)

```
! Reconnect all SDW2 cables to 3850 original ports

! On 3850:
configure terminal
interface range te<X>/<Y>, te<A>/<B>, gi<C>/<D>  ! All SDW2 ports
  no shutdown
end

! Wait for BGP to re-establish (1-2 minutes)
show ip bgp summary
```

### Validation Checklist

- [ ] 0101a Eth1/4: up (DIA-1) ⏱️ Time: ______ minutes
- [ ] 0101b Eth1/4: up (DIA-2)
- [ ] 0101b Eth1/6: up (Transport VLAN 630)
- [ ] 0101b Eth1/14: up (B2B VLAN 634)
- [ ] Po2: vPC operational across 0101a/b (VLANs 631-633)
- [ ] 0102a Eth1/20: up (Management)
- [ ] BGP neighbor 10.253.239.46: Established
- [ ] BGP prefixes received: 692
- [ ] BGP update-source: Vlan632
- [ ] BFD session up (300ms)
- [ ] DIA circuits passing traffic
- [ ] Internet connectivity validated
- [ ] Total BGP neighbors on 0101a: 2 (SDW1 + SDW2)
- [ ] Total BGP prefixes: ~1384
- [ ] Old 3850: All SD-WAN disconnected

**Status Update:** "SDW2 fully migrated to new cores. Both BGP sessions up. All DIA circuits operational. SD-WAN migration complete. ✅"

---

## Step 3.10: Shutdown Old 3850 SVIs (10:45 PM - 11:00 PM)

**Objective:** Gracefully shutdown all SVIs on old 3850 to complete L3 migration

**Risk:** MINIMAL - All routing now active on new cores

### Pre-Checks (10:45 PM)

**Verify New Cores Handling All Traffic:**
```
! On 0101a:
show interface vlan 10 | include rate
show interface vlan 163 | include rate
show interface vlan 555 | include rate

→ Should show significant traffic

show hsrp brief
→ All HSRPs Active on 0101a

show ip route summary
→ Full routing table present
```

**Verify No Critical Dependencies Remain:**
```
! On 3850:
show ip ospf neighbor
→ Should show 0 neighbors

show ip bgp summary
→ Should show 0 neighbors or no BGP session

show ip route summary
→ Note current routes for comparison
```

### Shutdown All SVIs on 3850 (10:50 PM)

**Announce:** "Shutting down all gateway IPs on old 3850. All traffic now on new cores."

**Procedure:**
```
! On 3850:
configure terminal

! Management
interface vlan 555
  shutdown

! Production VLANs
interface vlan 10
  shutdown
interface vlan 61
  shutdown
interface vlan 62
  shutdown
interface vlan 63
  shutdown
interface vlan 163
  shutdown

! WAN VLANs
interface vlan 550
  shutdown
interface vlan 551
  shutdown
interface vlan 552
  shutdown
interface vlan 553
  shutdown

! SD-WAN VLANs
interface vlan 620
  shutdown
interface vlan 621
  shutdown
interface vlan 622
  shutdown
interface vlan 623
  shutdown
interface vlan 624
  shutdown
interface vlan 630
  shutdown
interface vlan 631
  shutdown
interface vlan 632
  shutdown
interface vlan 633
  shutdown
interface vlan 634
  shutdown

! Internet/DMZ
interface vlan 3
  shutdown

! Voice VLANs
interface vlan 954
  shutdown

! VxRail/VMware
interface vlan 1502
  shutdown
interface vlan 1503
  shutdown
interface vlan 1504
  shutdown

! Partner VPN
interface vlan 560
  shutdown
interface vlan 562
  shutdown

! DNA Center
interface vlan 574
  shutdown
interface vlan 591
  shutdown

! Additional VLANs
interface vlan 575
  shutdown

! (Continue for all remaining SVIs)

end
copy running-config startup-config
```

### Validation (10:55 PM)

**On 3850:**
```
show ip interface brief | include Vlan
→ All SVIs should show "administratively down"

show ip route summary
→ Routing table should be minimal (only connected/local)

show interface vlan 10 | include rate
→ Should show no traffic or minimal
```

**On New Cores:**
```
! On both 0101a and 0101b:
show interface vlan 10 | include rate
show interface vlan 163 | include rate
show interface vlan 555 | include rate

→ Traffic should be unchanged (all on new cores now)

show ip arp summary
→ ARP entries stable

show hsrp brief
→ 0101a: Active, 0101b: Standby - no changes
```

**Application Validation:**
```
! From test devices:
- Ping gateways (should succeed via new cores)
- Test internet connectivity
- Test application access
- Verify no impact to operations
```

### Validation Checklist

- [ ] All SVIs shutdown on 3850 ⏱️ Time: ______ seconds
- [ ] New cores: Traffic unchanged
- [ ] HSRP: Stable on new cores
- [ ] No routing on 3850
- [ ] Applications functioning normally
- [ ] No incidents reported
- [ ] NOC confirms stable operations

**Status Update:** "Old 3850 SVIs shutdown. All L3 routing now on new Nexus cores. ✅"

---

## Step 3.11: Comprehensive L3 Validation (11:00 PM - 12:00 AM)

**Objective:** Complete end-to-end validation of entire L3 migration

### Routing Protocol Validation (11:00 PM)

**OSPF Complete Status:**
```
! On 0101a:
show ip ospf neighbor

Expected:
Neighbor ID     State    Interface
10.253.9.193    FULL/    Vlan550
10.253.9.197    FULL/    Vlan551

! On 0101b:
show ip ospf neighbor

Expected:
Neighbor ID     State    Interface
10.253.9.201    FULL/    Vlan552
10.253.9.205    FULL/    Vlan553

! Total: 4 OSPF adjacencies across both cores
```

**OSPF Route Count:**
```
! On both cores:
show ip route ospf | count
→ Should match expected AVPN route count
```

**BGP Complete Status:**
```
! On 0101a:
show ip bgp summary

Expected:
Neighbor        AS    State    PfxRcd  Up/Down
10.253.238.46 65520  Estab    692     XX:XX:XX
10.253.239.46 65520  Estab    692     XX:XX:XX

show ip route bgp | count
→ Should show ~1384 BGP routes
```

**BFD Session Status:**
```
! On 0101a:
show bfd neighbors

Expected sessions:
- 10.253.9.193 (OSPF VLAN 550)
- 10.253.9.197 (OSPF VLAN 551)
- 10.253.238.46 (BGP SDW1)
- 10.253.239.46 (BGP SDW2)

! On 0101b:
show bfd neighbors

Expected sessions:
- 10.253.9.201 (OSPF VLAN 552)
- 10.253.9.205 (OSPF VLAN 553)

All sessions should show: Up, 300ms interval, multiplier 3
```

### Static Route Validation (11:10 PM)

**On Both Cores:**
```
show running-config | include "ip route" | count
→ CRITICAL: Must return 174

show ip route static | count
→ Should show 174 static routes

show ip route static | include tag
→ All routes should have "tag 1000"

show ip route 151.110.239.1
→ Next hop: directly connected via VLAN 10
```

### Loopback and Router-ID Validation (11:15 PM)

**On 0101a:**
```
show interface loopback0
→ 10.253.9.61/32 - up/up

show ip route 10.253.9.61
→ Connected, via Loopback0

show ip ospf | include Router ID
→ Router ID: 10.253.9.61

show ip bgp | include router-id
→ local router-id: 10.253.9.61
```

**On 0101b:**
```
show interface loopback0
→ 10.253.9.62/32 - up/up

show ip route 10.253.9.62
→ Connected, via Loopback0

show ip ospf | include Router ID
→ Router ID: 10.253.9.62

show ip bgp | include router-id
→ local router-id: 10.253.9.62
```

### HSRP Validation (11:20 PM)

**On 0101a:**
```
show hsrp brief

Critical VLANs:
Interface   Grp Pri P State    Active          Standby         Virtual IP
Vlan10      10  115 P Active   local           10.253.0.3      151.110.239.254
Vlan555     555 115 P Active   local           10.253.0.3      10.253.0.1
Vlan622     622 115 P Active   local           10.253.0.3      10.253.238.49
Vlan632     632 115 P Active   local           10.253.0.3      10.253.239.49

→ All HSRPs should show Active, priority 115
→ No flapping, stable for 2+ hours
```

**On 0101b:**
```
show hsrp brief

→ All HSRPs should show Standby, priority 105
→ Active peer: 10.253.0.2
→ No flapping, stable
```

### Gateway Connectivity Tests (11:25 PM)

**From Multiple VLANs:**
```
! VLAN 10 (DC Internal):
ping 151.110.239.254 -c 100
→ 0% packet loss, <1ms latency

! VLAN 61 (Storage):
ping 172.18.61.254 -c 100
→ 0% packet loss

! VLAN 555 (Management):
ping 10.253.0.1 -c 100
→ 0% packet loss

! VLAN 163 (Production):
ping 151.110.163.254 -c 100
→ 0% packet loss
```

### WAN Connectivity Tests (11:30 PM)

**Internet Connectivity:**
```
! From new cores:
ping 8.8.8.8 source-interface vlan 10
ping 1.1.1.1 source-interface vlan 10

traceroute 8.8.8.8
→ Path should exit via AVPN or SD-WAN
```

**AVPN Connectivity:**
```
! Test routes via OSPF:
traceroute 10.127.138.25
→ Should route via AVPN

ping 10.127.138.25 -c 100
→ 0% packet loss
```

**SD-WAN Connectivity:**
```
! Test routes via BGP:
traceroute <remote-site-IP>
→ Should route via SD-WAN

! From SD-WAN routers:
- Test BGP routes propagating
- Verify branch connectivity
```

### Port-Channel and vPC Validation (11:35 PM)

**Core Switch vPCs:**
```
! On both 0101a and 0101b:
show vpc

vPC domain 101:
- vPC Peer-link: up
- vPC keep-alive: up
- vPC role: primary (0101a), secondary (0101b)

show vpc consistency-parameters global
→ All parameters: Success

show port-channel summary

Expected:
Po100 - vPC peer-link (Eth1/49-50)
Po1   - SDW1 service vPC (Eth1/9)
Po2   - SDW2 service vPC (Eth1/10)
Po101 - To fiber access 0103a (Eth1/51)
Po102 - To fiber access 0103b (Eth1/52)
Po103 - To copper access 0102a (Eth1/53)
Po104 - To copper access 0102b (Eth1/54)

All should show: (SU) - up
```

**Access Switch vPCs:**
```
! On 0102a/b (copper):
show vpc
→ vPC domain 102: up, consistent

! On 0103a/b (fiber):
show vpc
→ vPC domain 103: up, consistent
```

### Interface Traffic Validation (11:40 PM)

**WAN Uplinks:**
```
! On 0101a:
show interface ethernet 1/1 | include rate  ! AVPN primary
show interface ethernet 1/2 | include rate  ! Internet primary
show interface ethernet 1/3 | include rate  ! SDW1 DIA-1
show interface ethernet 1/4 | include rate  ! SDW2 DIA-1

! On 0101b:
show interface ethernet 1/1 | include rate  ! AVPN secondary
show interface ethernet 1/2 | include rate  ! Internet secondary
show interface ethernet 1/3 | include rate  ! SDW1 DIA-2
show interface ethernet 1/4 | include rate  ! SDW2 DIA-2

→ All should show active input/output traffic
```

**SVI Traffic:**
```
! On both cores:
show interface vlan 10 | include rate
show interface vlan 163 | include rate
show interface vlan 555 | include rate
show interface vlan 622 | include rate
show interface vlan 632 | include rate

→ All should show steady traffic flow
```

### Application and Service Validation (11:45 PM)

**Critical Infrastructure:**
- [ ] DNS servers responding (10.251.252.33, 10.251.253.33)
- [ ] TACACS servers reachable
- [ ] NTP servers synchronizing
- [ ] SNMP monitoring operational
- [ ] Syslog collection working

**End-User Services:**
- [ ] Web applications accessible
- [ ] Database connections stable
- [ ] File shares accessible
- [ ] Email services operational
- [ ] Voice/UC services functional

**Network Services:**
- [ ] Wireless controllers (6 WLCs) operational
- [ ] Load balancers (2x F5) operational
- [ ] Firewalls (EMEAFW1/2) passing traffic
- [ ] DNA Center cluster (3 nodes) accessible
- [ ] VxRail cluster accessible

### System Health Check (11:50 PM)

**On New Cores:**
```
! On both 0101a and 0101b:
show logging | include % | tail 100
→ No critical errors

show environment
→ All power supplies, fans, temperatures: OK

show system resources
→ CPU < 50%, Memory usage normal

show processes cpu sorted
→ No processes consuming excessive CPU

show ip arp summary
→ ARP entries stable and reasonable

show mac address-table count
→ MAC table populated appropriately
```

**On Old 3850:**
```
show logging | include % | tail 50
→ Should be quiet (no traffic)

show processes cpu sorted
→ CPU should be minimal
```

### Final Routing Table Comparison (11:55 PM)

**Compare Route Counts:**
```
! On new cores:
show ip route summary

! Compare against baseline from 3850:
- Total routes should match or exceed
- Static: 174
- OSPF: (AVPN routes)
- BGP: ~1384 (692 × 2)
- Connected/Local: (all SVIs)
```

### Validation Checklist

**Routing Protocols:**
- [ ] OSPF: 4 neighbors total (2 per core)
- [ ] BGP: 2 neighbors on 0101a (SDW1 + SDW2)
- [ ] BFD: All sessions up (6 total)
- [ ] Static routes: 174 on both cores
- [ ] Loopback: .61 (0101a), .62 (0101b) operational
- [ ] Router-IDs correct in OSPF and BGP

**High Availability:**
- [ ] HSRP: 0101a Active (115), 0101b Standby (105)
- [ ] vPC: All 3 domains operational
- [ ] Port-channels: All up
- [ ] Redundant paths: All functional

**WAN Connectivity:**
- [ ] AVPN: 4 links operational
- [ ] Internet: 2 links operational
- [ ] SD-WAN: 2 routers, 4 DIA circuits operational
- [ ] BGP: 1384 prefixes total

**Traffic Flow:**
- [ ] All WAN uplinks passing traffic
- [ ] All SVIs passing traffic
- [ ] Applications functioning
- [ ] No packet loss on gateway pings

**System Health:**
- [ ] No critical errors in logs
- [ ] Environmental status: OK
- [ ] Resource utilization: Normal
- [ ] NOC confirms normal operations

**Status Update:** "Comprehensive L3 validation complete. All routing protocols operational. All applications functional. ✅"

---

## Step 3.12: Promote New Cores to STP Root (12:00 AM - 12:30 AM)

**Objective:** Make new Nexus cores the STP root bridge for all VLANs

**Current:** Old 3850 is STP root (priority 8192)
**Target:** New core 0101a primary root (priority 8192), 0101b secondary root (priority 16384)

**Risk:** LOW - Brief (1-2 seconds) topology reconvergence

### Pre-Checks (12:00 AM)

**Current STP Status:**
```
! On 3850:
show spanning-tree summary

→ Should show: This bridge is the root

show spanning-tree vlan 10 | include Bridge
→ Priority: 8192 (current root)
```

**New Core STP Status:**
```
! On 0101a and 0101b:
show spanning-tree summary

→ Should show current priority (not root)

show spanning-tree vlan 10 | include Bridge
→ Note current priority
```

### Set New STP Priorities (12:05 AM)

**Announce:** "Changing STP root to new cores. Expect 1-2 second reconvergence."

**On 0101a (Primary Root):**
```
configure terminal
spanning-tree vlan 1-3967 priority 8192
end
copy running-config startup-config
```

**On 0101b (Secondary Root):**
```
configure terminal
spanning-tree vlan 1-3967 priority 16384
end
copy running-config startup-config
```

⏱️ **Start Timer**

**Wait for STP Convergence:** 15-30 seconds

### Monitor STP Reconvergence (12:06 AM)

**Watch topology change:**
```
! On 0101a:
show spanning-tree summary

→ Should transition to: This bridge is the root

show spanning-tree vlan 10

→ Bridge ID Priority: 8192
→ This bridge is the root
```

**Elapsed Time to Convergence:** ______ seconds

### Increase Priority on Old 3850 (12:10 AM)

**Lower old 3850 priority:**
```
! On 3850:
configure terminal
spanning-tree vlan 1-4094 priority 32768
end
copy running-config startup-config
```

### Validation (12:15 AM)

**New Cores:**
```
! On 0101a:
show spanning-tree summary

→ This bridge is the root
→ Root bridge for: (all VLANs)

show spanning-tree vlan 10

Bridge ID:
- Priority: 8192
- This bridge is the root

! On 0101b:
show spanning-tree summary

→ Root bridge for: none
→ Root ID Priority: 8192 (points to 0101a)

show spanning-tree vlan 10

Root ID:
- Priority: 8192
- Address: (0101a MAC)
```

**Old 3850:**
```
show spanning-tree summary

→ Root bridge for: none
→ Not the root anymore

show spanning-tree vlan 10

Root ID:
- Priority: 8192
- Address: (0101a MAC)
```

**Check All Ports Stable:**
```
! On all switches:
show spanning-tree inconsistentports
→ Should be empty

show spanning-tree vlan 10 | include FWD
→ All ports in forwarding state
```

**Test Connectivity:**
```
! From multiple devices:
ping 151.110.239.254 -c 100
→ No packet loss during/after STP change
```

### Validation Checklist

- [ ] 0101a: STP root (priority 8192) ⏱️ Convergence: ______ seconds
- [ ] 0101b: STP secondary (priority 16384)
- [ ] Old 3850: Not root (priority 32768)
- [ ] All ports forwarding
- [ ] No spanning-tree inconsistencies
- [ ] No packet loss during transition
- [ ] Applications unaffected

**Status Update:** "New Nexus cores are now STP root. Old 3850 demoted. ✅"

---

## Step 3.13: Final Validation & Documentation (12:30 AM - 1:30 AM)

**Objective:** Complete final end-to-end testing and document migration results

### Complete System Validation (12:30 AM)

**Architecture Verification:**
```
! Verify complete new topology:

Core Layer (0101a/b):
- vPC domain 101: operational
- OSPF: 4 neighbors total
- BGP: 2 neighbors (SD-WAN)
- HSRP: Active/Standby
- STP: Root bridge (0101a)
- All WAN uplinks: operational

Fiber Access (0103a/b):
- vPC domain 103: operational
- F5 load balancers: dual-homed
- Firewalls: dual-homed
- DNA Center: connected
- Uplinks to cores: operational

Copper Access (0102a/b):
- vPC domain 102: operational
- WLCs: dual-homed (4 × 1G + 2 × 10G)
- SD-WAN management: connected
- Uplinks to cores: operational
```

### Performance Testing (12:45 AM)

**Throughput Tests:**
```
! From test servers:
- Large file transfers between VLANs
- Measure throughput and latency
- Compare against baseline

! Internet speed tests:
- Test via DIA circuits
- Verify 24Gbps aggregate available
- Test failover between circuits
```

**Latency Tests:**
```
! Ping tests with statistics:
ping 151.110.239.254 -c 1000
→ Average latency < 1ms

ping 8.8.8.8 -c 100
→ Latency consistent

! AVPN latency:
ping <remote-site> -c 100
→ Verify no degradation
```

### Failover Testing (1:00 AM)

**HSRP Failover Test:**
```
! On 0101a:
configure terminal
interface vlan 10
  shutdown
end

! Watch HSRP transition:
! On 0101b:
show hsrp brief
→ Should transition to Active

! Test connectivity:
ping 151.110.239.254
→ Should succeed (brief interruption)

! Restore:
! On 0101a:
configure terminal
interface vlan 10
  no shutdown
end

! Verify return to Active on 0101a
```

**vPC Failover Test:**
```
! Shutdown one member of Po1 (SDW1 service):
! On 0101a:
configure terminal
interface ethernet 1/9
  shutdown
end

! Verify traffic continues via 0101b:
show port-channel 1 brief
show vpc 1
→ One member down, Po1 still up

! Restore:
interface ethernet 1/9
  no shutdown
end
```

### Documentation (1:10 AM)

**Capture Final Configurations:**
```
! On both new cores:
show running-config > flash:POST-MIGRATION-<timestamp>.cfg
copy running-config tftp://10.253.0.x/0101a-post-migration.cfg
copy running-config tftp://10.253.0.x/0101b-post-migration.cfg

! On old 3850:
copy running-config tftp://10.253.0.x/3850-post-migration.cfg
```

**Capture Show Commands:**
```
! On 0101a:
show version > flash:post-migration-show-version.txt
show vpc > flash:post-migration-show-vpc.txt
show ip route > flash:post-migration-show-ip-route.txt
show ip ospf neighbor > flash:post-migration-show-ospf.txt
show ip bgp summary > flash:post-migration-show-bgp.txt
show hsrp brief > flash:post-migration-show-hsrp.txt
```

**Document Changes Made:**
```
Migration Log:
- Start time: [timestamp]
- End time: [timestamp]
- Total duration: [hours]
- Downtime: [seconds during HSRP activation]

Devices Migrated:
✅ 2x AVPN routers (NLEACOAMS0011H/0012H)
✅ 2x Internet routers (NLEACEAMS0001R/0002R)
✅ 2x SD-WAN routers (Amidcnrm0101/0102)
✅ All L3 routing (OSPF, BGP, HSRP)
✅ 174 static routes
✅ STP root bridge

Issues Encountered:
- [List any issues]
- [Resolutions applied]

Validation Results:
✅ OSPF: 4 neighbors operational
✅ BGP: 2 neighbors, 1384 prefixes
✅ HSRP: Active/Standby operational
✅ vPC: 3 domains operational
✅ Static routes: 174 present
✅ Applications: All functional
```

### Final Health Check (1:20 AM)

**Monitor for Stability:**
```
! Over 10-minute window:

! On new cores:
- Watch HSRP (no flapping)
- Watch BGP (stable, no resets)
- Watch OSPF (stable adjacencies)
- Watch traffic rates (consistent)
- Watch error counters (none incrementing)
- Watch CPU/memory (normal)

! On access switches:
- vPC stable
- Port-channels stable
- No errors

! On old 3850:
- Minimal activity
- No unexpected traffic
```

### Validation Checklist

**Migration Complete:**
- [ ] All WAN uplinks migrated
- [ ] All L3 routing active on new cores
- [ ] OSPF: 4 neighbors, stable
- [ ] BGP: 2 neighbors, 1384 prefixes, stable
- [ ] HSRP: Active/Standby, no flapping
- [ ] Static routes: 174 present and operational
- [ ] vPC: 3 domains operational
- [ ] STP: New cores are root
- [ ] Old 3850: SVIs shutdown, demoted

**Testing Complete:**
- [ ] Gateway connectivity: 100% success
- [ ] Internet connectivity: Operational
- [ ] AVPN connectivity: Operational
- [ ] SD-WAN connectivity: Operational
- [ ] Application testing: All pass
- [ ] Failover testing: Successful
- [ ] Performance: Meets/exceeds baseline

**Documentation:**
- [ ] Configurations backed up
- [ ] Show command outputs captured
- [ ] Migration log completed
- [ ] Issues/resolutions documented
- [ ] Team debrief notes recorded

**Status Update:** "Final validation complete. All tests passed. Migration successful. ✅"

---

## Step 3.14: Maintenance Window Closure (1:30 AM - 2:00 AM)

**Objective:** Formally close maintenance window and transition to BAU

### Final Team Briefing (1:30 AM)

**Status Review:**
- Lead Engineer: Summary of migration
- Core Engineer: Report on new core health
- Access Engineer: Report on access layer health
- Validation Engineer: Report on test results
- Old 3850 Engineer: Report on old environment status

**Decisions:**
- [ ] Migration declared successful
- [ ] Ready to transition to BAU operations
- [ ] Old 3850 to remain powered on for 1 week as backup
- [ ] NOC handoff approved

### Send Completion Notification (1:35 AM)

**Send "Maintenance Complete" Message:**

```
Subject: Amsterdam IDC Network Migration - Maintenance COMPLETE ✅

The scheduled maintenance window for Amsterdam IDC network migration
has been completed successfully.

Start Time: Saturday 6:00 PM
Completion Time: Sunday 1:30 AM
Total Duration: 7.5 hours
Actual Downtime: <5 seconds (during gateway cutover at 8:36 PM)

Activities Completed:
✅ Migrated all WAN uplinks to new Nexus core switches
✅ Activated gateway IPs on new infrastructure
✅ Transferred all Layer 3 routing functions (OSPF, BGP, HSRP)
✅ Migrated 174 static routes
✅ Promoted new cores to STP root bridge
✅ Completed comprehensive validation testing

Current Status:
- New Cisco Nexus core switches: Fully operational
- All WAN links: Operational (AVPN, Internet, SD-WAN)
- All routing protocols: Stable
- All applications: Functional
- Old 3850 stack: Demoted, on standby for 1 week

Next Steps:
- Monitoring period: 1 week
- Old 3850 decommission: [planned date]
- Post-implementation review: [scheduled date]

The network is now operating on the new infrastructure.
No further impact is expected.

Thank you for your cooperation.

Contact: Network Team
```

**Update Status Page:**
- Status: "Maintenance Complete"
- Message: "Network upgrade completed successfully"
- Services: "All operational"

### Handoff to NOC (1:40 AM)

**NOC Briefing:**
```
Items to Monitor (Next 24 hours):
1. HSRP stability on new cores
   - Should remain Active on 0101a, Standby on 0101b
   - No flapping expected

2. BGP sessions (10.253.238.46, 10.253.239.46)
   - Should remain Established
   - Prefix count: 692 each

3. OSPF neighbors (4 total)
   - Should remain FULL
   - 2 on 0101a, 2 on 0101b

4. BFD sessions (6 total)
   - All should remain Up
   - Interval: 300ms

5. vPC health (3 domains)
   - Domain 101 (cores): peer-link Up
   - Domain 102 (copper): peer-link Up
   - Domain 103 (fiber): peer-link Up

6. Old 3850 stack
   - Should remain idle
   - Do NOT power off without approval

Escalation Contacts:
- Core Engineer: [contact]
- Lead Engineer: [contact]
- Emergency: [contact]

Alert Thresholds:
- BGP session down: P1 - Immediate escalation
- OSPF neighbor down: P1 - Immediate escalation
- HSRP flapping: P2 - Escalate if >3 flaps/hour
- vPC peer-link down: P1 - Immediate escalation
```

### Create Follow-Up Tasks (1:45 AM)

**Post-Migration Tasks:**
```
Week 1:
- [ ] Day 1: Monitor all routing protocols hourly
- [ ] Day 2-7: Monitor routing protocols 4x daily
- [ ] Verify old 3850 remains stable in standby mode
- [ ] Collect performance metrics for comparison

Week 2:
- [ ] Schedule post-implementation review meeting
- [ ] Analyze performance data
- [ ] Document lessons learned
- [ ] Plan old 3850 decommissioning

Week 3:
- [ ] Execute old 3850 decommission (if stable)
- [ ] Update network documentation
- [ ] Update network diagrams
- [ ] Archive migration documentation

Week 4:
- [ ] Begin Singapore site planning (Phase 4)
- [ ] Apply lessons learned to Singapore runbook
```

### Final Checks (1:50 AM)

**Quick Status Verification:**
```
! On 0101a and 0101b:
show vpc brief
show ip ospf neighbor
show ip bgp summary
show hsrp brief
show logging | include % | tail 20

→ All should be stable, no new errors
```

**Team Confirmation:**
- [ ] All team members: Ready to release
- [ ] All documentation: Complete
- [ ] All backups: Secured
- [ ] NOC: Briefed and ready to monitor
- [ ] Escalation contacts: Confirmed

### Declare Maintenance Complete (1:55 AM)

**Official Closure:**
- **Lead Engineer Declaration:** "Amsterdam IDC L3 migration is officially complete. Maintenance window closed. Thank you to all team members."
- **Time:** [timestamp]
- **Status:** SUCCESS ✅

### Team Sign-Off (2:00 AM)

**Acknowledgments:**
- [ ] Lead Engineer: Signed off
- [ ] Core Engineer: Signed off
- [ ] Access Engineer: Signed off
- [ ] Old 3850 Engineer: Signed off
- [ ] Validation Engineer: Signed off
- [ ] Scribe: Signed off

---

## MAINTENANCE WINDOW COMPLETE

**Total Duration:** ~8 hours (6:00 PM - 2:00 AM)
**Status:** ✅ SUCCESS
**Downtime:** <5 seconds (HSRP cutover)

---

## Appendix A: Emergency Rollback Procedure

**If Critical Issues Arise During Migration:**

### Full Rollback Steps

1. **Reconnect Old 3850 (2 minutes)**
   ```
   ! On 3850:
   configure terminal
   interface range vlan 1-4094
     no shutdown
   end

   ! Restore STP priority:
   spanning-tree vlan 1-4094 priority 8192

   ! Reconnect WAN cables to original ports
   ```

2. **Shutdown New Core SVIs (1 minute)**
   ```
   ! On BOTH 0101a and 0101b:
   configure terminal
   interface range vlan 1-4094
     shutdown
   end
   ```

3. **Verify Traffic Restored (5 minutes)**
   ```
   ! On 3850:
   show hsrp brief
   show ip ospf neighbor
   show ip bgp summary
   show spanning-tree summary

   ! Test connectivity from devices
   ```

4. **Investigate Issue**
   - Review logs on new cores
   - Identify root cause
   - Develop fix
   - Schedule retry

### Partial Rollback (Per Service)

**If only one service fails:**
- Rollback that specific service only
- Keep successful migrations in place
- Continue with remaining steps after fix

---

## Appendix B: Key IP Addresses Quick Reference

| Service | Primary (0101a) | Secondary (0101b) | Virtual (HSRP) |
|---------|----------------|-------------------|----------------|
| Management | 10.253.0.2 | 10.253.0.3 | 10.253.0.1 |
| DC Internal | 151.110.239.253 | 151.110.239.252 | 151.110.239.254 |
| SDW1 Service | 10.253.238.50 | 10.253.238.50 | 10.253.238.49 |
| SDW2 Service | 10.253.239.50 | 10.253.239.50 | 10.253.239.49 |
| AVPN Link 1 | 10.253.9.194 | 10.253.9.194 | N/A (P2P) |
| AVPN Link 2 | 10.253.9.198 | 10.253.9.198 | N/A (P2P) |
| AVPN Link 3 | 10.253.9.202 | 10.253.9.202 | N/A (P2P) |
| AVPN Link 4 | 10.253.9.206 | 10.253.9.206 | N/A (P2P) |
| Loopback0 | 10.253.9.61 | 10.253.9.62 | N/A |

**BGP Neighbors:**
- SDW1: 10.253.238.46 (AS 65520, via VLAN 622)
- SDW2: 10.253.239.46 (AS 65520, via VLAN 632)

**Static Route Gateway:**
- Firewall: 151.110.239.1 (174 routes)

---

## Appendix C: Port Assignment Quick Reference

### Core Switches (0101a/0101b)

| Port | Device | Purpose | VLAN/Trunk |
|------|--------|---------|------------|
| Eth1/1 | AVPN router | Primary/Secondary | Trunk: 550-551,553,560,562,620-634 |
| Eth1/2 | Internet router | Primary/Secondary | Access: 3 |
| Eth1/3 | SDW1/SDW2 DIA-1 | 6Gbps circuit | Access: 3 |
| Eth1/4 | SDW2/SDW1 DIA-2 | 6Gbps circuit | Access: 3 |
| Eth1/5 | SDW1 Transport | VLAN 620 | Access: 620 |
| Eth1/6 | SDW2 Transport | VLAN 630 | Access: 630 |
| Eth1/9 | Po1 member | SDW1 service vPC | Trunk: 621-623 |
| Eth1/10 | Po2 member | SDW2 service vPC | Trunk: 631-633 |
| Eth1/13 | SDW1 B2B | Single-homed | Access: 624 |
| Eth1/14 | SDW2 B2B | Single-homed | Access: 634 |
| Eth1/49-50 | Peer-link | vPC member | All VLANs |
| Eth1/51 | To 0103a | Uplink Po101 | All VLANs |
| Eth1/52 | To 0103b | Uplink Po102 | All VLANs |
| Eth1/53 | To 0102a | Uplink Po103 | All VLANs |
| Eth1/54 | To 0102b | Uplink Po104 | All VLANs |

---

**END OF PHASE 3 L3 MIGRATION RUNBOOK**

**Document Version:** 2.0 (CORRECTED)
**Last Updated:** 2026-04-20
**Status:** READY FOR EXECUTION
