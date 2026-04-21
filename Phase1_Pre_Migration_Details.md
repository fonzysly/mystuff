# Phase 1: Pre-Migration Preparation (Offline)

**Duration:** 2-3 days of work (scheduled weeks before maintenance)
**Risk Level:** NONE (all offline activities)
**Impact:** No production impact

---

## Objectives

1. Configure all 6 Nexus switches completely offline
2. Validate configurations against requirements
3. Create detailed documentation and runbooks
4. Prepare rollback procedures

---

## Step 1.1: Hardware Verification (2 hours)

### Inventory Checklist

**Core Switches (2):**
- [ ] N9K-C93240YC-FX2 (AMIDCnsm0101a) - Serial: _______
- [ ] N9K-C93240YC-FX2 (AMIDCnsm0101b) - Serial: _______

**Fiber Access (2):**
- [ ] N9K-C93180YC-FX3 (AMIDCnsm0103a) - Serial: _______
- [ ] N9K-C93180YC-FX3 (AMIDCnsm0103b) - Serial: _______

**Copper Access (2):**
- [ ] N9K-C93108TC-FX3 (AMIDCnsm0102a) - Serial: _______
- [ ] N9K-C93108TC-FX3 (AMIDCnsm0102b) - Serial: _______

**Optics & Transceivers:**
- [ ] 10G SFP+ SR (qty: ____)
- [ ] 10G SFP+ LR (qty: ____)
- [ ] 25G SFP28 (qty: ____)
- [ ] 100G QSFP28 DAC for vPC peer links (qty: 9 - three per pair)

**Cables:**
- [ ] Fiber patch cables - multimode (qty: ____)
- [ ] Fiber patch cables - singlemode (qty: ____)
- [ ] Cat6 copper patches for L2 trunk (qty: 4)
- [ ] Console cables (qty: 6)

**Other:**
- [ ] Console server
- [ ] Rack mounting hardware
- [ ] Power cables (dual per switch)
- [ ] Cable labels

---

## Step 1.2: Upgrade New Nexus Switches to NX-OS 10.5(4)(M) (3-4 hours)

**Duration:** 3-4 hours (all 6 switches upgraded offline before deployment)
**Risk Level:** NONE (offline activity, no production impact)
**Impact:** No production impact

### Objectives

- Upgrade all 6 new Nexus switches to NX-OS 10.5(4)(M) before configuration
- Ensure consistent software version across all new switches
- Use latest stable NX-OS release for feature support and bug fixes
- Complete before applying production configurations

### Target Software Version

**NX-OS Version:** 10.5(4)(M) - Latest recommended release
- **Core Switches (N9K-C93240YC-FX2):** nxos64-cs.10.5.4.M.bin
- **Fiber Access (N9K-C93180YC-FX3):** nxos64-cs.10.5.4.M.bin
- **Copper Access (N9K-C93108TC-FX3):** nxos64-cs.10.5.4.M.bin

**Download Location:** Cisco Software Download Center
- Navigate to: Switches > Data Center Switches > Nexus 9000 Series Switches
- Select appropriate model, then NX-OS Software
- Download: nxos64-cs.10.5.4.M.bin (~2.2 GB)
- Verify MD5 checksum from Cisco download page

### Pre-Upgrade Preparation

**Stage Image on TFTP/SCP Server:**
```bash
# On Linux/management server (10.253.0.x):
cd /tftpboot
# Copy nxos64-cs.10.5.4.M.bin to this directory
chmod 644 nxos64-cs.10.5.4.M.bin
md5sum nxos64-cs.10.5.4.M.bin
# Verify MD5 matches Cisco's published hash
```

**Console Cable Setup:**
- Connect console cables to all 6 switches
- Use console server or direct console connection
- Document console port assignments

### Upgrade Procedure (Per Switch)

**Repeat for all 6 switches:** AMIDCnsm0101a, 0101b, 0102a, 0102b, 0103a, 0103b

#### Step 1: Check Current Version and Space

```
switch# show version
Cisco Nexus Operating System (NX-OS) Software
# Note current version

switch# dir bootflash:
# Verify sufficient space (~3GB free required)
```

#### Step 2: Copy New Image to Bootflash

**Via TFTP:**
```
switch# copy tftp://10.253.0.x/nxos64-cs.10.5.4.M.bin bootflash: vrf management
# Transfer takes 10-15 minutes depending on network speed
```

**Via SCP (if preferred):**
```
switch# copy scp://user@10.253.0.x/nxos64-cs.10.5.4.M.bin bootflash: vrf management
```

#### Step 3: Verify Image Integrity

```
switch# show file bootflash:nxos64-cs.10.5.4.M.bin md5sum
# Compare with Cisco's published MD5 checksum
```

#### Step 4: Install New Image

**Using install all command (recommended for NX-OS):**
```
switch# install all nxos bootflash:nxos64-cs.10.5.4.M.bin

# Switch will:
# 1. Verify image integrity
# 2. Set boot variables
# 3. Reload automatically
# 4. Boot into new version (~5-8 minutes)

# Confirm prompts when asked
```

**Alternative: Manual method:**
```
switch# configure terminal
switch(config)# boot nxos bootflash:nxos64-cs.10.5.4.M.bin
switch(config)# end
switch# copy running-config startup-config
switch# reload
This command will reboot the system. (y/n)?  [n] y
```

#### Step 5: Post-Upgrade Verification

**After switch reloads (~5-8 minutes), verify:**

```
switch# show version
Cisco Nexus Operating System (NX-OS) Software
...
  NXOS: version 10.5(4)M
  NXOS image file is: bootflash:///nxos64-cs.10.5.4.M.bin

switch# show boot
# Verify boot variables point to new image

switch# show module
# Verify all modules are active/ok

switch# show environment
# Check power supplies, fans, temperatures - all should be OK
```

### Upgrade Order and Tracking

**Recommended Order:**

1. **Core Switches First:**
   - [ ] AMIDCnsm0101a - Console: _______ - Start: _____ End: _____
   - [ ] AMIDCnsm0101b - Console: _______ - Start: _____ End: _____

2. **Fiber Access:**
   - [ ] AMIDCnsm0103a - Console: _______ - Start: _____ End: _____
   - [ ] AMIDCnsm0103b - Console: _______ - Start: _____ End: _____

3. **Copper Access:**
   - [ ] AMIDCnsm0102a - Console: _______ - Start: _____ End: _____
   - [ ] AMIDCnsm0102b - Console: _______ - Start: _____ End: _____

**Estimated Time:**
- Image transfer: 10-15 minutes per switch
- Reload/upgrade: 5-8 minutes per switch
- Verification: 5 minutes per switch
- **Total per switch:** ~25-30 minutes
- **Total for 6 switches:** 3-4 hours (can parallelize with multiple console sessions)

### Validation Checklist (Per Switch)

- [ ] NX-OS version shows 10.5(4)M
- [ ] Boot variable correctly set to nxos64-cs.10.5.4.M.bin
- [ ] All modules status: active/ok
- [ ] All power supplies: OK
- [ ] All fans: OK
- [ ] Temperature sensors: Normal range
- [ ] Console access functional
- [ ] Management interface responsive (after config in Step 1.3)

### Cleanup (Optional)

**After successful upgrade, remove old images to free space:**
```
switch# dir bootflash:
# Note old image filename(s)

switch# delete bootflash:nxos.X.X.X.bin
# Only delete after confirming new version is stable and boot variables are correct
```

### Troubleshooting

**If switch doesn't boot after upgrade:**

1. Power cycle the switch
2. Interrupt boot process (Ctrl-C during boot)
3. At loader prompt:
```
loader> dir
# List available images

loader> boot bootflash:nxos64-cs.10.5.4.M.bin
# Manually boot the image
```

4. Once booted, verify boot variables:
```
switch# show boot
switch# configure terminal
switch(config)# boot nxos bootflash:nxos64-cs.10.5.4.M.bin
switch(config)# end
switch# copy running-config startup-config
```

**If image transfer fails:**
- Verify management network connectivity
- Check TFTP/SCP server accessibility
- Verify sufficient bootflash: space
- Try alternative transfer method (SCP vs TFTP)

### Critical Notes

- **Perform upgrades BEFORE applying production configurations**
- All switches will be offline during this phase (no production impact)
- Use console access exclusively during upgrade (no SSH until configured)
- Keep original factory image as backup until migration complete
- Document actual software versions after upgrade for records
- If any switch fails upgrade, do not proceed to configuration phase

### Post-Upgrade Status

**All switches should show:**
```
switch# show version | include NXOS
  NXOS: version 10.5(4)M
  NXOS image file is: bootflash:///nxos64-cs.10.5.4.M.bin
  NXOS compile time: [date stamp]
```

---

## Step 1.3: Base Configuration - Core Switches (4-6 hours)

### Initial Setup

**Console Access:**
```
enable
configure terminal
hostname AMIDCnsm0101a  ! or 0101b
boot nxos bootflash:nxos.10.X.X.bin
```

**Note:** Switch should already be running NX-OS 10.5(4)(M) from Step 1.2

### Enable Required Features

```
feature tacacs+
feature ssh
feature interface-vlan
feature hsrp
feature ospf
feature bgp
feature bfd
feature vpc
feature lacp
feature lldp
```

### Management Configuration

**Management VRF and Interface:**
```
vrf context management
  ip route 0.0.0.0/0 10.253.0.1

interface mgmt0
  vrf member management
  ip address 10.253.0.2/25  ! 0101a
  ! ip address 10.253.0.3/25  ! 0101b
  no shutdown
```

**TACACS+ Authentication:**
```
tacacs-server host 10.251.252.33 key 7 <encrypted-key>
tacacs-server host 10.251.253.33 key 7 <encrypted-key>

aaa group server tacacs+ TACACS-SERVERS
  server 10.251.252.33
  server 10.251.253.33
  use-vrf management
  source-interface mgmt0

aaa authentication login default group TACACS-SERVERS local
aaa authorization commands default group TACACS-SERVERS local
aaa accounting default group TACACS-SERVERS

username admin password 5 <encrypted-password> role network-admin
```

**SSH Configuration:**
```
ssh key rsa 2048
ssh login-attempts 3
ssh timeout 300

line vty
  exec-timeout 30
  session-limit 10
```

**NTP Configuration:**
```
ntp server 10.251.252.11 use-vrf management
ntp server 10.251.253.11 use-vrf management
ntp source-interface mgmt0
```

**DNS Configuration:**
```
ip domain-name company.local
ip name-server 151.110.17.11 151.110.17.75
```

**SNMP Configuration:**
```
snmp-server community <community-string> ro
snmp-server location "Amsterdam IDC - Rack XX"
snmp-server contact "Network Team"
snmp-server host 10.253.0.x traps version 2c <community-string>
```

**Logging Configuration:**
```
logging server 10.253.0.x 6
logging source-interface loopback0
logging timestamp milliseconds
logging monitor 6
logging logfile messages 6 size 16384
```

### vPC Domain 101 Configuration

**On AMIDCnsm0101a:**
```
vpc domain 101
  role priority 100
  peer-keepalive destination 10.253.0.3 source 10.253.0.2 vrf management
  peer-gateway
  auto-recovery reload-delay 300
  ip arp synchronize
  delay restore 120
```

**On AMIDCnsm0101b:**
```
vpc domain 101
  role priority 200
  peer-keepalive destination 10.253.0.2 source 10.253.0.3 vrf management
  peer-gateway
  auto-recovery reload-delay 300
  ip arp synchronize
  delay restore 120
```

### vPC Peer Link (Po100)

**On both 0101a and 0101b:**
```
interface port-channel100
  description vPC-PEER-LINK-TO-PARTNER
  switchport mode trunk
  switchport trunk allowed vlan 1-4094
  spanning-tree port type network
  vpc peer-link

interface Ethernet1/47
  description vPC-PEER-LINK-MEMBER-1
  switchport mode trunk
  switchport trunk allowed vlan 1-4094
  channel-group 100 mode active
  no shutdown

interface Ethernet1/48
  description vPC-PEER-LINK-MEMBER-2
  switchport mode trunk
  switchport trunk allowed vlan 1-4094
  channel-group 100 mode active
  no shutdown
```

### Spanning Tree Configuration

```
spanning-tree mode rapid-pvst
spanning-tree vlan 1-4094 priority 16384  ! Secondary root initially
spanning-tree port type edge bpduguard default
spanning-tree loopguard default
spanning-tree pathcost method long
```

### VLAN Database

**Create all production VLANs:**
```
vlan 3
  name Internet-OUT-IN
vlan 4
  name DMZ
vlan 10
  name DC-Internal-151.110.239.0-24
vlan 61
  name Storage-172.18.61.0-24
vlan 62
  name Cluster-Heartbeat-172.18.62.0-25
vlan 63
  name iLO-OOB-172.18.62.128-25
vlan 163
  name DC-Production-151.110.163.0-24
vlan 555
  name Network-Management-10.253.0.0-25
vlan 550-553
  name AVPN-PTP-Links
vlan 560,562
  name Business-Partner-VPN-Transit
vlan 574
  name DNA-Center-Enterprise
vlan 591
  name DNA-Center-Intracluster
vlan 620-624
  name SDW1-Transport-Service
vlan 630-634
  name SDW2-Transport-Service
vlan 950-959,969
  name Voice-UC-VLANs
vlan 1502
  name VxRail-OOB-Management
vlan 1503
  name VxRail-ESXi-Management
vlan 1504
  name VxRail-vMotion
! (Continue for all remaining VLANs)
```

### Loopback Interfaces

**On AMIDCnsm0101a:**
```
interface loopback0
  description OSPF-Router-ID
  ip address 10.253.9.60/32

interface loopback7777
  description Service-Testing-Loopback
  ip address 10.253.250.5/32
```

**On AMIDCnsm0101b:**
```
interface loopback0
  description OSPF-Router-ID
  ip address 10.253.9.61/32

interface loopback7777
  description Service-Testing-Loopback
  ip address 10.253.250.6/32
```

### HSRP Configuration on SVIs

**WAITING FOR: Real IP allocations from customer**

**Template - On AMIDCnsm0101a:**
```
interface vlan 10
  description DC-Internal-151.110.239.0/24
  no shutdown
  ip address <0101a-REAL-IP>/24
  no ip redirects
  hsrp 10
    ip 151.110.239.254
    priority 110
    preempt
    authentication md5 key-string 7 <encrypted-key>

interface vlan 61
  description Storage-172.18.61.0/24
  no shutdown
  ip address <0101a-REAL-IP>/24
  no ip redirects
  hsrp 61
    ip 172.18.61.254
    priority 110
    preempt
    authentication md5 key-string 7 <encrypted-key>

interface vlan 555
  description Network-Management-10.253.0.0/25
  no shutdown
  ip address 10.253.0.2/25
  no ip redirects
  hsrp 555
    ip 10.253.0.1
    priority 110
    preempt
    authentication md5 key-string 7 <encrypted-key>

! (Repeat for ALL SVIs with similar pattern)
```

**Template - On AMIDCnsm0101b:**
```
interface vlan 10
  description DC-Internal-151.110.239.0/24
  no shutdown
  ip address <0101b-REAL-IP>/24
  no ip redirects
  hsrp 10
    ip 151.110.239.254
    priority 100
    authentication md5 key-string 7 <encrypted-key>

! (Repeat for ALL SVIs - priority 100 for standby)
```

**Critical Note:** Keep ALL SVIs in NO SHUTDOWN state initially in pre-config. They will be activated during Step 3.5 of maintenance window.

### OSPF Configuration

**On AMIDCnsm0101a:**
```
router ospf 10
  router-id 10.253.9.60
  log-adjacency-changes detail
  auto-cost reference-bandwidth 100000
  passive-interface default
  bfd
  redistribute static route-map REDISTRIBUTE-STATIC-TO-OSPF10

interface vlan 550
  description AVPN-PTP-NLEACOAMS0011H-Link1
  ip address 10.253.9.34/30
  ip ospf authentication message-digest
  ip ospf message-digest-key 1 md5 3 <encrypted-key>
  ip ospf network point-to-point
  ip ospf 10 area 0.0.0.0
  no ip ospf passive-interface
  ip ospf bfd

interface vlan 552
  description AVPN-PTP-NLEACOAMS0011H-Link2
  ip address 10.253.9.42/30
  ip ospf authentication message-digest
  ip ospf message-digest-key 1 md5 3 <encrypted-key>
  ip ospf network point-to-point
  ip ospf 10 area 0.0.0.0
  no ip ospf passive-interface
  ip ospf bfd
```

**On AMIDCnsm0101b:**
```
router ospf 10
  router-id 10.253.9.61
  log-adjacency-changes detail
  auto-cost reference-bandwidth 100000
  passive-interface default
  bfd
  redistribute static route-map REDISTRIBUTE-STATIC-TO-OSPF10

interface vlan 551
  description AVPN-PTP-NLEACOAMS0012H-Link1
  ip address 10.253.9.38/30
  ip ospf authentication message-digest
  ip ospf message-digest-key 1 md5 3 <encrypted-key>
  ip ospf network point-to-point
  ip ospf 10 area 0.0.0.0
  no ip ospf passive-interface
  ip ospf bfd

interface vlan 553
  description AVPN-PTP-NLEACOAMS0012H-Link2
  ip address 10.253.9.46/30
  ip ospf authentication message-digest
  ip ospf message-digest-key 1 md5 3 <encrypted-key>
  ip ospf network point-to-point
  ip ospf 10 area 0.0.0.0
  no ip ospf passive-interface
  ip ospf bfd
```

### BGP Configuration

**On AMIDCnsm0101a:**
```
route-map SDWAN_TO_CORE permit 10
route-map CORE_TO_SDWAN permit 10
route-map REDISTRIBUTE-STATIC-TO-BGP permit 10

router bgp 64721
  router-id 10.253.9.60
  log-neighbor-changes
  address-family ipv4 unicast
    network 10.127.138.25/32
    network 148.179.254.48/28
    redistribute static route-map REDISTRIBUTE-STATIC-TO-BGP
    redistribute connected route-map CONNECTED_CORE

  neighbor 10.253.238.46
    description SDW1-VLAN622-BGP-PEER
    remote-as 65520
    password 3 <encrypted-password>
    update-source vlan622
    address-family ipv4 unicast
      soft-reconfiguration inbound
      send-community both
      route-map SDWAN_TO_CORE in
      route-map CORE_TO_SDWAN out
    bfd
```

**On AMIDCnsm0101b:**
```
route-map SDWAN_TO_CORE permit 10
route-map CORE_TO_SDWAN permit 10
route-map REDISTRIBUTE-STATIC-TO-BGP permit 10

router bgp 64721
  router-id 10.253.9.61
  log-neighbor-changes
  address-family ipv4 unicast
    network 10.127.138.25/32
    network 148.179.254.48/28
    redistribute static route-map REDISTRIBUTE-STATIC-TO-BGP
    redistribute connected route-map CONNECTED_CORE

  neighbor 10.253.239.46
    description SDW2-VLAN632-BGP-PEER
    remote-as 65520
    password 3 <encrypted-password>
    update-source vlan632
    address-family ipv4 unicast
      soft-reconfiguration inbound
      send-community both
      route-map SDWAN_TO_CORE in
      route-map CORE_TO_SDWAN out
    bfd
```

### Static Routes

**WAITING FOR: Complete list of ~100+ static routes from current 3850**

**Apply to BOTH cores (identical):**
```
ip route 10.x.x.x/x 151.110.239.1 name TO-FIREWALL
ip route 172.x.x.x/x 151.110.239.1 name TO-FIREWALL
! (Repeat for all ~100 static routes)
```

### BFD Configuration

```
bfd interval 300 min_rx 100 multiplier 3
```

### Uplink Interface Configurations

**AVPN Uplinks:**
```
! On 0101a:
interface Ethernet1/1
  description AVPN-NLEACOAMS0011H-TRUNK
  switchport mode trunk
  switchport trunk allowed vlan 550,552,560,562,620-624,630-634
  no shutdown

! On 0101b:
interface Ethernet1/2
  description AVPN-NLEACOAMS0012H-TRUNK
  switchport mode trunk
  switchport trunk allowed vlan 551,553,560,562,620-624,630-634
  no shutdown
```

**Internet Uplinks:**
```
! On 0101a:
interface Ethernet1/5
  description INTERNET-PRIMARY-NLEACEAMS0001R
  switchport mode trunk
  switchport trunk allowed vlan 3,4,12,13
  no shutdown

! On 0101b:
interface Ethernet1/5
  description INTERNET-SECONDARY-NLEACEAMS0002R
  switchport mode trunk
  switchport trunk allowed vlan 3,4,12,13
  no shutdown
```

**SD-WAN Single Link Uplinks:**
```
! On 0101a (SDW1 connections):
interface Ethernet1/6
  description SDW1-MGMT-PRIMARY
  switchport mode trunk
  switchport trunk native vlan 99
  switchport trunk allowed vlan 620,621
  spanning-tree port type edge trunk
  spanning-tree bpduguard enable
  no shutdown

interface Ethernet1/7
  description SDW1-DIA-CIRCUIT-1-VLAN3
  switchport mode trunk
  switchport trunk allowed vlan 3
  spanning-tree port type edge trunk
  no shutdown

interface Ethernet1/17
  description SDW1-DIA-CIRCUIT-2-VLAN3
  switchport mode trunk
  switchport trunk allowed vlan 3
  spanning-tree port type edge trunk
  no shutdown

! On 0101b (SDW2 connections):
interface Ethernet1/6
  description SDW2-MGMT-SECONDARY
  switchport mode trunk
  switchport trunk native vlan 99
  switchport trunk allowed vlan 630,631
  spanning-tree port type edge trunk
  spanning-tree bpduguard enable
  no shutdown

interface Ethernet1/7
  description SDW2-DIA-CIRCUIT-1-VLAN3
  switchport mode trunk
  switchport trunk allowed vlan 3
  spanning-tree port type edge trunk
  no shutdown

interface Ethernet1/17
  description SDW2-DIA-CIRCUIT-2-VLAN3
  switchport mode trunk
  switchport trunk allowed vlan 3
  spanning-tree port type edge trunk
  no shutdown
```

**SD-WAN Port-Channels (vPC):**
```
! On BOTH 0101a and 0101b:

interface port-channel50
  description SDW1-SERVICE-LAN-Po50-VLANs622-623
  switchport mode trunk
  switchport trunk native vlan 99
  switchport trunk allowed vlan 622,623
  spanning-tree port type edge trunk
  spanning-tree bpduguard enable
  vpc 50

interface port-channel51
  description SDW2-SERVICE-LAN-Po51-VLANs623-632
  switchport mode trunk
  switchport trunk native vlan 99
  switchport trunk allowed vlan 623,632
  spanning-tree port type edge trunk
  spanning-tree bpduguard enable
  vpc 51

interface port-channel52
  description SDW1-B2B-MPLS-Po52-VLAN624
  switchport mode trunk
  switchport trunk native vlan 99
  switchport trunk allowed vlan 624
  spanning-tree port type edge trunk
  spanning-tree bpduguard enable
  vpc 52

interface port-channel53
  description SDW2-B2B-MPLS-Po53-VLAN634
  switchport mode trunk
  switchport trunk native vlan 99
  switchport trunk allowed vlan 634
  spanning-tree port type edge trunk
  spanning-tree bpduguard enable
  vpc 53

! On 0101a (Po50/52 member interfaces):
interface Ethernet1/10
  description SDW1-Po50-MEMBER-TO-SDW1-Te0/0/3
  switchport mode trunk
  channel-group 50 mode active
  no shutdown

interface Ethernet1/11
  description SDW1-Po52-MEMBER-TO-SDW1-Te0/0/5
  switchport mode trunk
  channel-group 52 mode active
  no shutdown

! On 0101b (Po50/52 member interfaces):
interface Ethernet1/10
  description SDW1-Po50-MEMBER-TO-SDW1-Te0/0/4
  switchport mode trunk
  channel-group 50 mode active
  no shutdown

interface Ethernet1/11
  description SDW1-Po52-MEMBER-TO-SDW1-Te0/0/X
  switchport mode trunk
  channel-group 52 mode active
  no shutdown

! Similar configuration for Po51/53 on Eth1/12-13
```

**Downlinks to Access Layers:**
```
! On BOTH 0101a and 0101b:

interface port-channel102
  description UPLINK-TO-COPPER-ACCESS-0102
  switchport mode trunk
  switchport trunk allowed vlan 1-4094
  spanning-tree port type network
  vpc 102

interface port-channel103
  description UPLINK-TO-FIBER-ACCESS-0103
  switchport mode trunk
  switchport trunk allowed vlan 1-4094
  spanning-tree port type network
  vpc 103

! On 0101a:
interface Ethernet1/53
  description DOWNLINK-TO-0102a-Eth1/49
  switchport mode trunk
  channel-group 102 mode active
  no shutdown

interface Ethernet1/54
  description DOWNLINK-TO-0102b-Eth1/49
  switchport mode trunk
  channel-group 102 mode active
  no shutdown

interface Ethernet1/49
  description DOWNLINK-TO-0103a-Eth1/49
  switchport mode trunk
  channel-group 103 mode active
  no shutdown

interface Ethernet1/50
  description DOWNLINK-TO-0103b-Eth1/49
  switchport mode trunk
  channel-group 103 mode active
  no shutdown

! On 0101b (mirror configuration):
interface Ethernet1/53
  description DOWNLINK-TO-0102a-Eth1/50
  switchport mode trunk
  channel-group 102 mode active
  no shutdown

interface Ethernet1/54
  description DOWNLINK-TO-0102b-Eth1/50
  switchport mode trunk
  channel-group 102 mode active
  no shutdown

interface Ethernet1/49
  description DOWNLINK-TO-0103a-Eth1/50
  switchport mode trunk
  channel-group 103 mode active
  no shutdown

interface Ethernet1/50
  description DOWNLINK-TO-0103b-Eth1/50
  switchport mode trunk
  channel-group 103 mode active
  no shutdown
```

### Save Configuration

```
copy running-config startup-config
```

---

## Step 1.4: Access Layer Configuration (4 hours total)

**Note:** All access switches should already be running NX-OS 10.5(4)(M) from Step 1.2

### Fiber Access Switches (0103a/0103b) - 2 hours

**Basic Setup:**
```
hostname AMIDCnsm0103a  ! or 0103b

feature interface-vlan
feature vpc
feature lacp
feature lldp

vrf context management
  ip route 0.0.0.0/0 10.253.0.1

interface mgmt0
  vrf member management
  ip address 10.253.0.4/25  ! 0103a
  ! ip address 10.253.0.5/25  ! 0103b
  no shutdown
```

**vPC Domain 103:**
```
! On 0103a:
vpc domain 103
  role priority 100
  peer-keepalive destination 10.253.0.5 source 10.253.0.4 vrf management
  auto-recovery reload-delay 240

! On 0103b:
vpc domain 103
  role priority 200
  peer-keepalive destination 10.253.0.4 source 10.253.0.5 vrf management
  auto-recovery reload-delay 240
```

**vPC Peer Link:**
```
! On BOTH 0103a and 0103b:
interface port-channel100
  description vPC-PEER-LINK
  switchport mode trunk
  switchport trunk allowed vlan 1-4094
  spanning-tree port type network
  vpc peer-link

interface Ethernet1/53-54
  switchport mode trunk
  channel-group 100 mode active
  no shutdown
```

**Uplinks to Core:**
```
! On BOTH 0103a and 0103b:
interface port-channel103
  description UPLINK-TO-CORE-0101
  switchport mode trunk
  switchport trunk allowed vlan 1-4094
  spanning-tree port type network
  vpc 103

! On 0103a:
interface Ethernet1/49
  description UPLINK-TO-CORE-0101a-Eth1/49
  switchport mode trunk
  channel-group 103 mode active
  no shutdown

interface Ethernet1/50
  description UPLINK-TO-CORE-0101b-Eth1/49
  switchport mode trunk
  channel-group 103 mode active
  no shutdown

! On 0103b (mirrored):
interface Ethernet1/49
  description UPLINK-TO-CORE-0101a-Eth1/50
  switchport mode trunk
  channel-group 103 mode active
  no shutdown

interface Ethernet1/50
  description UPLINK-TO-CORE-0101b-Eth1/50
  switchport mode trunk
  channel-group 103 mode active
  no shutdown
```

**VLANs:**
```
vlan 10,61-63,163,192,555,574,591,953,1502-1504
! (Only VLANs needed for fiber access layer)
```

**Spanning Tree:**
```
spanning-tree mode rapid-pvst
spanning-tree vlan 1-4094 priority 24576
spanning-tree port type edge bpduguard default
```

### Copper Access Switches (0102a/0102b) - 2 hours

**Basic Setup:**
```
hostname AMIDCnsm0102a  ! or 0102b

feature interface-vlan
feature vpc
feature lacp
feature lldp

vrf context management
  ip route 0.0.0.0/0 10.253.0.1

interface mgmt0
  vrf member management
  ip address 10.253.0.6/25  ! 0102a
  ! ip address 10.253.0.7/25  ! 0102b
  no shutdown
```

**vPC Domain 102:**
```
! On 0102a:
vpc domain 102
  role priority 100
  peer-keepalive destination 10.253.0.7 source 10.253.0.6 vrf management
  auto-recovery reload-delay 240

! On 0102b:
vpc domain 102
  role priority 200
  peer-keepalive destination 10.253.0.6 source 10.253.0.7 vrf management
  auto-recovery reload-delay 240
```

**vPC Peer Link:**
```
! On BOTH 0102a and 0102b:
interface port-channel100
  description vPC-PEER-LINK
  switchport mode trunk
  switchport trunk allowed vlan 1-4094
  spanning-tree port type network
  vpc peer-link

interface Ethernet1/53-54
  switchport mode trunk
  channel-group 100 mode active
  no shutdown
```

**Uplinks to Core:**
```
! On BOTH 0102a and 0102b:
interface port-channel102
  description UPLINK-TO-CORE-0101
  switchport mode trunk
  switchport trunk allowed vlan 1-4094
  spanning-tree port type network
  vpc 102

! On 0102a:
interface Ethernet1/49
  description UPLINK-TO-CORE-0101a-Eth1/53
  switchport mode trunk
  channel-group 102 mode active
  no shutdown

interface Ethernet1/50
  description UPLINK-TO-CORE-0101b-Eth1/54
  switchport mode trunk
  channel-group 102 mode active
  no shutdown

! On 0102b:
interface Ethernet1/49
  description UPLINK-TO-CORE-0101a-Eth1/54
  switchport mode trunk
  channel-group 102 mode active
  no shutdown

interface Ethernet1/50
  description UPLINK-TO-CORE-0101b-Eth1/53
  switchport mode trunk
  channel-group 102 mode active
  no shutdown
```

**L2 Trunk to Old 3850:**
```
! On BOTH 0102a and 0102b:
interface port-channel200
  description L2-TRUNK-TO-OLD-3850-STACK
  switchport mode trunk
  switchport trunk allowed vlan 1-4094
  spanning-tree port type normal
  vpc 200

! On 0102a:
interface Ethernet1/45
  description TO-OLD-3850-Gi3/0/1
  switchport mode trunk
  channel-group 200 mode active

interface Ethernet1/46
  description TO-OLD-3850-Gi4/0/1
  switchport mode trunk
  channel-group 200 mode active

! On 0102b:
interface Ethernet1/45
  description TO-OLD-3850-Gi3/0/2
  switchport mode trunk
  channel-group 200 mode active

interface Ethernet1/46
  description TO-OLD-3850-Gi4/0/2
  switchport mode trunk
  channel-group 200 mode active
```

**VLANs:**
```
vlan 3-4,7,10,12-13,80-81,99,169,555-556,560-562,570-575,590-591,950-959,969
! (All VLANs needed for copper access layer)
```

**Spanning Tree:**
```
spanning-tree mode rapid-pvst
spanning-tree vlan 1-4094 priority 24576
spanning-tree port type edge bpduguard default
```

---

## Step 1.5: Documentation Preparation (4-6 hours)

### Port Migration Matrix

Create comprehensive mapping document:

| Device Name | Type | Current Location | Current Port | VLANs | New Location | New Port | Po# | Notes |
|-------------|------|------------------|--------------|-------|--------------|----------|-----|-------|
| AMIDC-WLC.1 | WLC | 3850 | Gi5/0/1-2 | 99,all | 0102a/b | Po1 | vPC | Dual-homed |
| AMIDC-WLC.2 | WLC | 3850 | Gi5/0/3-4 | 99,all | 0102a/b | Po2 | vPC | Dual-homed |
| BigIP-1 | LB | 3850 | Te1/0/13-14 | 3,4,10 | 0103a/b | Po10 | vPC | Dual-homed |
| EMEAFW1 | Firewall | 3850 | Te1/0/8 + Po71 | Multiple | 0102a/b | Po71 | vPC | Critical |
| ... | ... | ... | ... | ... | ... | ... | ... | ... |

### IP Allocation Document

**HSRP Real IPs Required:**

| VLAN | Subnet | Mask | Current GW | 0101a Real IP | 0101b Real IP | HSRP Virtual | Priority |
|------|--------|------|------------|---------------|---------------|--------------|----------|
| 10 | 151.110.239.0 | /24 | .254 | TBD | TBD | .254 | 110/100 |
| 61 | 172.18.61.0 | /24 | .254 | TBD | TBD | .254 | 110/100 |
| 62 | 172.18.62.0 | /25 | .126 | TBD | TBD | .126 | 110/100 |
| 63 | 172.18.62.128 | /25 | .254 | TBD | TBD | .254 | 110/100 |
| 163 | 151.110.163.0 | /24 | .254 | TBD | TBD | .254 | 110/100 |
| 555 | 10.253.0.0 | /25 | .1 | .2 | .3 | .1 | 110/100 |
| ... | ... | ... | ... | ... | ... | ... | ... |

**ACTION REQUIRED:** Customer to provide .2 and .3 IPs for each subnet

### Validation Checklists

Create phase-specific checklists (to be populated in separate documents)

### Rollback Procedures

Document per-phase rollback steps (to be detailed in separate document)

---

## Step 1.6: Configuration Review & Approval (4-8 hours)

### Peer Review Checklist

- [ ] Senior network engineer review completed
- [ ] All VLANs from current config migrated
- [ ] All SVIs configured with HSRP
- [ ] OSPF configuration verified (auth keys, areas)
- [ ] BGP configuration verified (passwords, route-maps)
- [ ] Static routes copied and verified
- [ ] vPC configuration validated
- [ ] Security team approval (TACACS+, SSH)
- [ ] No syntax errors in configs
- [ ] Configs saved to TFTP/backup location

### Management Approval

- [ ] Change request CR-________ submitted
- [ ] CAB approval obtained
- [ ] Maintenance window scheduled: Saturday ________ 6:00 PM - 6:00 AM
- [ ] Stakeholder notifications sent
- [ ] Rollback plan approved
- [ ] Team assignments confirmed

---

**PHASE 1 COMPLETE - Ready for Phase 2**
