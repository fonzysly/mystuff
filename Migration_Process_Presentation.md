# Amsterdam IDC Network Migration
## How The Migration Will Work

**Presenter:** Network Engineering Team
**Date:** 2026-04-14
**Duration:** 10-15 minutes
**Focus:** Migration Process & Execution

---

## Slide 1: Migration Overview

### What We're Doing

**Replacing:** 6-member Cisco Catalyst 3850 stack
**With:** 6 new Cisco Nexus switches (3-tier architecture)

**When:** Saturday evening maintenance window
**Duration:** 6-8 hours
**Impact:** 1-5 seconds during gateway cutover

### The Big Picture

```
OLD (Today)                    NEW (After Migration)

┌─────────────┐               ┌──────┐  ┌──────┐
│   3850      │               │ Core │  │ Core │
│   Stack     │───────────────│0101a │  │0101b │
│  (6 units)  │               └──┬───┘  └───┬──┘
└─────────────┘                  │          │
                                 ├────┬─────┤
                             ┌───▼──┐ │ ┌───▼──┐
                             │Access│ │ │Access│
                             │Fiber │ │ │Copper│
                             └──────┘ │ └──────┘
                                      │
                              (Devices move here)
```

---

## Slide 2: Migration Strategy - "L3 First, Cables Last"

### The Approach

**Key Principle:** Move routing FIRST, then move devices LATER

**Why This Works:**
- Old and new environments coexist during migration
- Can switch back if problems occur
- Devices migrate incrementally (low risk)

### The Phases

```
Phase 1: Preparation        Phase 2: Installation       Phase 3: L3 Migration ⭐
   (Offline)               (Days before Saturday)        (Saturday Evening)

 Configure new              Install new                  Move routing to
 switches offline           switches, build              new switches
                           Layer 2 bridge
 ├─ Zero impact            ├─ Zero impact               ├─ 1-5 sec impact
 └─ 2-3 days work          └─ 4-6 hours                 └─ 6-8 hours


Phase 4: Device Migration   Phase 5: Cleanup
  (Following Weeks)          (Week 5+)

 Move devices to             Remove old
 new access layers           equipment

 ├─ 30-60 sec/device         ├─ Zero impact
 └─ 3-5 days spread out      └─ 1 day
```

---

## Slide 3: Current State - What We Have Today

### Network Topology Now

```
                    INTERNET        AVPN/MPLS      SD-WAN
                        │               │             │
                        └───────┬───────┴─────────────┘
                                │
                          ┌─────▼─────┐
                          │  3850     │
                          │  Stack    │◄─── ALL Routing Happens Here
                          │ (6 units) │
                          └─────┬─────┘
                                │
                    ┌───────────┼───────────┐
                    │           │           │
                 Servers    Firewalls   Wireless
                              etc.
```

**Key Points:**
- Everything connects to 3850 stack
- Single point where ALL routing happens
- All WAN connections terminate here
- All devices connect here

---

## Slide 4: Phase 1 - Preparation (Offline)

### What Happens: Configure Everything Offline

**Duration:** 2-3 days work (done weeks before maintenance)
**Impact:** ZERO - No production connectivity

**Activities:**
1. Configure all 6 new Nexus switches completely
   - VLANs, IP addresses, routing protocols
   - HSRP (gateway redundancy)
   - vPC (link redundancy)

2. Peer review all configurations
   - Senior engineers validate
   - Compare against current state
   - Test in lab if possible

3. Create detailed runbooks
   - Step-by-step commands
   - Validation checks
   - Rollback procedures

**Deliverable:** 6 fully configured switches ready to deploy

---

## Slide 5: Phase 2 - Physical Installation

### What Happens: Install New Infrastructure

**Duration:** 4-6 hours (done days before Saturday maintenance)
**Impact:** ZERO - No production impact

**Activities:**

**Step 1: Rack and Power**
- Install 6 new switches in racks
- Connect power, console access
- Verify management connectivity

**Step 2: Build Layer 2 Bridge**
```
Old 3850 Stack
     │
     │ Layer 2 Trunk (8 Gbps)
     │ (4x 1G cables)
     │
New Switches
```
- Connect old and new with 1G copper cables
- Creates "bridge" between environments
- All VLANs flow between old and new

**Step 3: Form vPC Pairs**
- Connect new switches to each other
- Establish redundancy links
- Verify health

**Result:** New infrastructure ready, connected to old via Layer 2

---

## Slide 6: Phase 2 Result - Dual Environment

### Network State After Phase 2

```
                    INTERNET        AVPN/MPLS      SD-WAN
                        │               │             │
                        └───────┬───────┴─────────────┘
                                │
                          ┌─────▼─────┐
                          │  OLD      │◄─── Still doing ALL routing
                          │  3850     │
                          └─────┬─────┘
                                │
                         [Layer 2 Trunk]  ◄─── Bridge
                                │
                          ┌─────▼─────┐
                          │   NEW     │◄─── Installed but not routing yet
                          │  Nexus    │
                          └───────────┘
```

**Key Points:**
- Old 3850: Still handles all routing (business as usual)
- New switches: Installed and ready, but not active yet
- Layer 2 trunk: Allows both to communicate
- Users see no difference

---

## Slide 7: Phase 3 Overview - The Saturday Maintenance

### What Happens: Move Routing to New Infrastructure

**Date:** Saturday evening (TBD)
**Start Time:** 6:00 PM
**Duration:** 6-8 hours (10-12 hour window for safety)
**Impact:** 1-5 seconds during gateway cutover

### The Goal

Move everything that makes the network work:
- **WAN uplinks** (Internet, AVPN, SD-WAN)
- **Routing protocols** (OSPF, BGP)
- **Gateway IPs** (where devices send traffic)

### The Sequence

```
6:00 PM  ──► Team assembly & validation
6:30 PM  ──► Move WAN uplinks one-by-one
8:30 PM  ──► ACTIVATE GATEWAYS ⭐ (Critical moment: 1-5 sec impact)
10:00 PM ──► Complete remaining uplinks
11:00 PM ──► Validation & testing
12:30 AM ──► Optimize traffic paths
2:00 AM  ──► Completion
```

---

## Slide 8: Phase 3 Detailed Steps

### Step-by-Step Process

**Step 1: Move WAN Uplinks (6:30 PM - 10:00 PM)**

Move one cable at a time, test, then move next:

```
Order of Migration:
1. Primary Internet link     (20 min) ──► Test ──► ✓
2. Primary AVPN link         (40 min) ──► Test ──► ✓
3. Primary SD-WAN router     (60 min) ──► Test ──► ✓
4. Secondary Internet link   (15 min) ──► Test ──► ✓
5. Secondary AVPN link       (30 min) ──► Test ──► ✓
6. Secondary SD-WAN router   (45 min) ──► Test ──► ✓
```

**Result:** All WAN connections now on new cores

**Key Points:**
- Always maintain one active path
- Move primary first, validate, then secondary
- Can rollback each step if issues

---

## Slide 9: Phase 3 Critical Moment - Gateway Cutover

### Step 2: Activate Gateway IPs (8:30 PM)

**THIS IS THE MOMENT OF DOWNTIME (1-5 seconds)**

**What Happens:**
```
BEFORE:                          AFTER:
Devices talk to OLD gateway      Devices talk to NEW gateway

Device ──► Gateway on 3850       Device ──► Gateway on New Cores
```

**The Process:**
1. Enable gateway IPs on new cores
2. HSRP takes over (automatic failover)
3. Devices re-learn new gateway location (ARP)
4. Traffic flows through new cores

**Expected Impact:**
- **1-5 seconds:** Brief interruption as devices switch
- **ARP re-learning:** Devices discover new gateway
- **Most users won't notice:** Very brief

**What Users Experience:**
- Web page may pause briefly
- Slight lag in applications
- Connections re-establish automatically

---

## Slide 10: Phase 3 Result - New Infrastructure Active

### Network State After Phase 3

```
                    INTERNET        AVPN/MPLS      SD-WAN
                        │               │             │
                        └───────┬───────┴─────────────┘
                                │
                          ┌─────▼─────┐
                          │   NEW     │◄─── Now doing ALL routing ✓
                          │  Nexus    │
                          └─────┬─────┘
                                │
                         [Layer 2 Trunk]  ◄─── Bridge remains
                                │
                          ┌─────▼─────┐
                          │  OLD      │◄─── Now just Layer 2 switching
                          │  3850     │
                          └─────┬─────┘
                                │
                    ┌───────────┼───────────┐
                    │           │           │
                 Servers    Firewalls   Wireless
                              etc.
```

**Key Points:**
- New cores: Handle all routing now
- Old 3850: Demoted to just switching (devices still connected)
- Layer 2 trunk: Still active for device connectivity
- Routing protocols moved to new infrastructure

---

## Slide 11: Phase 3 Validation

### How We Verify Success

**Immediate Checks (During Maintenance):**
- [ ] All WAN uplinks operational on new cores
- [ ] OSPF adjacencies: 4 (AVPN routing protocol)
- [ ] BGP sessions: 2 (SD-WAN routing protocol)
- [ ] Gateway failover (HSRP) operational
- [ ] Internet connectivity working
- [ ] Internal routing working

**Application Testing:**
- [ ] Wireless controllers reachable
- [ ] Servers responding
- [ ] Firewalls passing traffic
- [ ] Storage accessible
- [ ] Voice calls working
- [ ] Critical applications operational

**Performance Validation:**
- [ ] CPU/Memory normal on new cores
- [ ] No errors in logs
- [ ] Traffic flowing correctly
- [ ] Response times normal

---

## Slide 12: Phase 4 - Device Migration (Following Weeks)

### What Happens: Move Devices to New Access Layer

**Duration:** 3-5 days work spread over weeks
**Impact:** 30-60 seconds per device

**The Process:**

```
BEFORE Phase 4:                  AFTER Phase 4:
Devices on old switch            Devices on new access layer

      NEW Cores                        NEW Cores
          │                                │
   [Layer 2 Trunk]                    ┌────┴────┐
          │                            │         │
      OLD 3850                    NEW Access  NEW Access
          │                       (Fiber)     (Copper)
      ┌───┴───┐                       │         │
      │       │                       └────┬────┘
   Servers  Firewalls                      │
                                    ┌──────┴───────┐
                                    │              │
                                 Servers      Firewalls
```

**Migration Order:**
1. **Week 1:** Non-critical devices (monitoring, test servers)
2. **Week 2:** VxRail servers (eliminate 4 ToR switches)
3. **Week 3:** Critical infrastructure (one at a time)
   - Wireless controllers (4 units)
   - Load balancers (migrate secondary first)
   - Firewalls (migrate backup first)
   - IPS devices

**Per Device:**
- Cable move: 30-60 seconds downtime
- Validation: 5-10 minutes
- Can be done during business hours (brief impact)

---

## Slide 13: Phase 5 - Decommission (Week 5+)

### What Happens: Remove Old Infrastructure

**Duration:** 1 day
**Impact:** ZERO

**Activities:**
1. Validate all devices migrated (old switch empty)
2. Remove Layer 2 trunk between old and new
3. Power down old 3850 stack
4. Remove old equipment from racks
5. Clean up cabling
6. Update documentation

**Result:** Migration complete, old infrastructure removed

---

## Slide 14: Timeline Summary

### Complete Project Schedule

```
┌─────────────────────────────────────────────────────────────┐
│                      PROJECT TIMELINE                        │
└─────────────────────────────────────────────────────────────┘

Week 1-2: Phase 1 - Preparation
├─ Configure switches offline
├─ Peer review
└─ Runbook creation
    Impact: ZERO
                              [WE ARE HERE]
                                   ↓
Week 3: Phase 2 - Installation
├─ Rack equipment
├─ Build Layer 2 trunk
└─ Validate connectivity
    Impact: ZERO
    Duration: 4-6 hours

Week 4: Phase 3 - L3 Migration ⭐
├─ Saturday Evening: 6:00 PM - 2:00 AM
├─ Move WAN uplinks
├─ Activate gateways
└─ Complete validation
    Impact: 1-5 seconds
    Duration: 8 hours

Weeks 5-7: Phase 4 - Device Migration
├─ Incremental device moves
├─ Non-critical first
└─ Critical infrastructure last
    Impact: 30-60 sec per device
    Duration: 3-5 days spread out

Week 8: Phase 5 - Cleanup
├─ Remove old equipment
└─ Documentation
    Impact: ZERO
    Duration: 1 day

TOTAL PROJECT: 8 weeks
```

---

## Slide 15: The Critical Path - Saturday Evening

### Hour-by-Hour Breakdown

```
6:00 PM │ Team Assembly & Pre-Checks
        │ • Verify old environment stable
        │ • Verify new switches ready
        │ • Take configuration backups
        │ • GO/NO-GO decision
        │
6:30 PM │ Move Primary WAN Uplinks
        │ • Internet link moved
        │ • AVPN link moved (brief OSPF convergence)
        │ • SD-WAN router 1 moved
        │
8:30 PM │ ⭐ ACTIVATE GATEWAY IPs ⭐
        │ • Enable HSRP on new cores
        │ • DOWNTIME: 1-5 seconds HERE
        │ • Devices switch to new gateways
        │ • Validate applications
        │
9:15 PM │ Move Secondary WAN Uplinks
        │ • Internet link moved
        │ • AVPN link moved
        │ • SD-WAN router 2 moved
        │
11:00PM │ Comprehensive Validation
        │ • Test all routing protocols
        │ • Test all applications
        │ • Performance check
        │ • 1 hour of testing
        │
12:30AM │ Traffic Optimization
        │ • Optimize spanning tree
        │ • Final adjustments
        │
1:30 AM │ Final Documentation
        │ • Record final state
        │ • Create completion report
        │
2:00 AM │ COMPLETION
        │ • Send success notification
        │ • Handoff to operations team
```

---

## Slide 16: Risk Mitigation - How We Stay Safe

### Safety Mechanisms Built In

**1. Parallel Operation**
```
OLD stays operational ──┐
                        ├──► Both work during migration
NEW brought online  ────┘

Can switch back if problems!
```

**2. Step-by-Step Validation**
```
Move one link ──► Test ──► ✓ Success? ──► Move next link
                     │
                     └──► ✗ Failed? ──► Rollback immediately
```

**3. Always Maintain Redundancy**
```
Move PRIMARY link first ──► Test ──► Still have SECONDARY
If primary fails ──────────────────► Traffic uses secondary
```

**4. Go/No-Go Checkpoints**
- Before starting: All systems green?
- Before gateway cutover: Routing working?
- Before secondary moves: Primary validated?

**5. Rollback Procedures**
Every step has a reversal plan:
```
Problem detected ──► Execute rollback ──► Back to old (< 5 min)
```

---

## Slide 17: What Could Go Wrong & How We Handle It

### Scenario Planning

| Scenario | Probability | Our Response |
|----------|-------------|--------------|
| **WAN link doesn't come up** | Low | Reconnect to old switch, continue with other links |
| **Routing protocol fails** | Low | Have correct credentials/configs, vendor support on call |
| **Gateway cutover causes issues** | Low | Disable new gateways, old takes over automatically |
| **Device compatibility issue** | Low | Device stays on old switch, migrate later in Phase 4 |
| **Takes longer than expected** | Medium | Have 10-12 hour window (expect 8 hours) |
| **Critical application fails** | Low | Immediate rollback to old infrastructure |

**Overall Strategy:**
- Conservative timeline (buffer time built in)
- Test at each step before proceeding
- Can stop and rollback at any point
- Team on bridge entire time

---

## Slide 18: Rollback Strategy

### If We Need to Go Back

**During Migration (Phase 3):**

**Rollback is EASY and FAST:**
```
Problem Detected
      ↓
Shutdown new gateway IPs (30 seconds)
      ↓
Reconnect WAN uplinks to old 3850 (2-3 minutes)
      ↓
Enable old routing (1 minute)
      ↓
Back to original state (Total: < 5 minutes)
```

**72-Hour Safety Window:**
- After Phase 3 completes
- Old equipment still connected
- Can roll back within 3 days if issues found
- After 72 hours: Commit point (rollback harder)

**Phase 4 (Device Migration):**
- Easy per-device rollback
- Just move cable back to old switch
- No impact to other devices

---

## Slide 19: Success Criteria

### How We Know We're Done

**Technical Success:**
- [ ] All 4 OSPF adjacencies operational (AVPN routing)
- [ ] Both BGP sessions established (SD-WAN routing)
- [ ] HSRP gateways active (automatic failover working)
- [ ] All WAN connections on new infrastructure
- [ ] Zero packet loss (except brief cutover)
- [ ] Performance normal or better

**Operational Success:**
- [ ] Internet access working
- [ ] AVPN connectivity working
- [ ] SD-WAN branches online
- [ ] Wireless operational
- [ ] Servers accessible
- [ ] Applications responding normally
- [ ] No critical incidents

**Business Success:**
- [ ] Downtime < 5 seconds (as expected)
- [ ] Completed within 8-hour window
- [ ] No user complaints
- [ ] All stakeholders notified
- [ ] Team consensus: Success

---

## Slide 20: Communication Plan

### Keeping Everyone Informed

**3 Weeks Before:**
```
Email to All Stakeholders
├─ What: Network infrastructure upgrade
├─ When: Saturday [DATE] 6PM-2AM
├─ Impact: 1-5 seconds during cutover
└─ Who to contact: Network team
```

**1 Week Before:**
```
Reminder Email
├─ Final date confirmation
├─ Expected timeline
└─ Status page link
```

**Day Before:**
```
Final Notice
└─ Maintenance begins tomorrow 6PM
```

**During Maintenance:**
```
6:00 PM: "Maintenance started"
8:30 PM: "Gateway cutover beginning (1-5 sec impact now)"
2:00 AM: "Maintenance completed successfully"
```

**After Completion:**
```
Success Notification (within 1 hour)
├─ Status: Complete
├─ Duration: X hours
├─ Impact: X seconds
├─ Issues: None / [list]
└─ Next steps: Device migration (following weeks)
```

---

## Slide 21: What We Need

### Management Support Required

**Approvals:**
- [ ] Approve maintenance window (Saturday evening, 10-12 hours)
- [ ] Approve brief service interruption (1-5 seconds)
- [ ] Approve team overtime (Saturday evening/night work)

**Communication Support:**
- [ ] Help notify business stakeholders
- [ ] Set expectations with user community
- [ ] Support team if escalations occur

**Post-Migration:**
- [ ] Allow 72-hour monitoring period
- [ ] Support Phase 4 device migrations (business hours work)
- [ ] Recognize team effort

**What We Commit:**
- Minimize downtime (< 5 seconds target)
- Complete within 8-hour window
- Immediate notification if issues
- Daily status reports (72 hours post)
- Comprehensive documentation

---

## Slide 22: Next Steps

### What Happens Now

**This Week:**
- [ ] Get management approval (this meeting)
- [ ] Schedule Saturday maintenance window
- [ ] Finalize remaining configurations
- [ ] Send 3-week advance notice

**Next Week:**
- [ ] Complete Phase 2 (physical installation)
- [ ] Final team training
- [ ] Runbook review
- [ ] Vendor support confirmation

**Week Before Maintenance:**
- [ ] Send 1-week reminder
- [ ] Final Go/No-Go checkpoint
- [ ] Team final briefing

**Maintenance Day (Saturday):**
- [ ] 5:00 PM: Team assembly
- [ ] 6:00 PM: BEGIN Phase 3
- [ ] ~2:00 AM: Complete
- [ ] Success notification sent

**Following Weeks:**
- [ ] 72-hour monitoring
- [ ] Phase 4: Device migration
- [ ] Phase 5: Cleanup

---

## Slide 23: Summary

### The Migration in 60 Seconds

**WHAT:**
Replace old 3850 stack with 6 new Nexus switches

**HOW:**
"L3 First, Cables Last" approach
- Move routing to new switches first (Saturday)
- Move devices later (following weeks)

**WHEN:**
Saturday evening, 6:00 PM - 2:00 AM (8 hours)

**IMPACT:**
1-5 seconds during gateway cutover at ~8:30 PM

**WHY THIS WORKS:**
- Old and new run in parallel (safe)
- Step-by-step validation (controlled)
- Can rollback at any time (low risk)
- Proven technology and approach

**WHAT WE NEED:**
- Maintenance window approval
- Accept brief service interruption
- Support team during execution

**CONFIDENCE LEVEL:**
High (95%+) - Detailed planning, expert team, proven approach

---

## Questions?

### Open Discussion

**Key Contacts:**
- Project Lead: [Name] - [Email] - [Phone]
- Network Manager: [Name] - [Email] - [Phone]

**Documentation:**
- Full migration plan: [Location]
- Technical runbooks: [Location]
- Rollback procedures: [Location]

**Thank you!**

Ready to answer any questions about:
- Specific steps in the process
- Risk mitigation strategies
- Timeline and schedule
- Technical details
- Resource requirements
