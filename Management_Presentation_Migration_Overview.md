# Amsterdam IDC Network Migration
## Executive Presentation for Management

**Presenter:** Network Engineering Team
**Date:** 2026-04-14
**Duration:** 15-20 minutes
**Audience:** Management, Stakeholders

---

## Slide 1: Executive Summary

### Project Overview
**Replacing Legacy Infrastructure with Modern Architecture**

- **What:** Migrate from 6-member Cisco Catalyst 3850 stack to Cisco Nexus vPC architecture
- **Where:** Amsterdam IDC (Primary site - Singapore to follow)
- **Why:** End-of-life hardware, capacity constraints, enable future initiatives
- **When:** Saturday evening maintenance window (6-8 hours)
- **Impact:** < 5 seconds downtime during gateway cutover

### Key Benefits
- **2x port capacity** for 10G+ connections
- **Active-active** forwarding (no wasted bandwidth)
- **Zero-downtime** upgrades capability
- **Modern platform** for DNA Center, SD-WAN, automation

---

## Slide 2: Business Drivers

### Why We Must Migrate Now

**1. Hardware End-of-Life**
- Current 3850 switches: End of support
- No security patches or bug fixes available
- Compliance risk

**2. Capacity Exhausted**
- 48/48 10G ports in production use (100% utilization)
- Cannot add new services (SD-WAN, DNA Center expansion)
- Blocking business initiatives

**3. Single Point of Failure**
- Stack architecture: One control plane
- Switch failure impacts entire data center
- No upgrade path without downtime

**4. Technology Debt**
- Platform does not support modern features
- Cannot meet future requirements (VXLAN, automation)
- Increasing operational complexity

---

## Slide 3: Current vs. Future State

### Current Environment (Legacy)

```
┌─────────────────────────────────────┐
│   6x Catalyst 3850 Stack            │
│   (Single Logical Switch)           │
│                                     │
│   • 48x 10G Ports (ALL USED)       │
│   • 192x 1G Ports                  │
│   • Single Control Plane           │
│   • Stack-based HA                 │
│   • STP Blocking on Some Links     │
└─────────────────────────────────────┘
          ↓ All Services
    WAN, Servers, Devices
```

**Limitations:**
- Port exhaustion (cannot grow)
- Upgrade requires downtime
- Single control plane risk

### Future Environment (Modern)

```
         ┌──────────────┐         ┌──────────────┐
         │   Core 0101a │←─ vPC ─→│   Core 0101b │
         │  (N9K-FX2)   │         │  (N9K-FX2)   │
         │   • 60 Ports │         │   • 60 Ports │
         └──────┬───────┘         └──────┬───────┘
                │                        │
         Active-Active Forwarding
                │                        │
         ┌──────┴────────┬───────────────┴──────┐
         │               │                      │
    ┌────▼────┐    ┌────▼────┐          ┌─────▼────┐
    │ Fiber   │    │ Fiber   │          │  Copper  │
    │ Access  │    │ Access  │          │  Access  │
    │ 0103a/b │    │ (ToR    │          │  0102a/b │
    │         │    │Replaced)│          │          │
    └─────────┘    └─────────┘          └──────────┘
```

**Improvements:**
- 2x port capacity (96x 10/25G)
- Dual control planes (true redundancy)
- Zero-downtime upgrades
- Modern features enabled

---

## Slide 4: Migration Strategy

### "L3 First, Cables Last" Approach

**Phase 1: Preparation (Offline - No Impact)**
- Configure new switches completely
- Test configurations offline
- Build Layer 2 bridge between old/new
- **Duration:** 2-3 days prep work
- **Impact:** ZERO

**Phase 2: Physical Install (Low Impact)**
- Install 6 new switches
- Establish management connectivity
- Create Layer 2 trunk to old environment
- **Duration:** 4-6 hours (done before maintenance)
- **Impact:** ZERO

**Phase 3: L3 Migration (Saturday Evening) ⭐**
- Move WAN uplinks to new cores
- Activate gateway IPs (HSRP)
- Transfer all routing functions
- Promote new switches to STP root
- **Duration:** 6-8 hours
- **Impact:** 1-5 seconds during cutover

**Phase 4: Device Migration (Following Weeks)**
- Move devices incrementally to new access layers
- One device at a time (30-60 sec each)
- **Duration:** 3-5 days spread over weeks
- **Impact:** Minimal per device

**Phase 5: Decommission (Week 5+)**
- Remove old 3850 stack
- Clean up, documentation
- **Duration:** 1 day
- **Impact:** ZERO

---

## Slide 5: Risk Mitigation

### How We Minimize Risk

**1. Parallel Operation**
- Old and new systems coexist via Layer 2 trunk
- Can switch back if issues occur
- 72-hour rollback window after L3 migration

**2. Incremental Validation**
- Test after each step before proceeding
- Go/No-Go decision points throughout
- Can pause migration at any phase

**3. Proven Technology**
- Cisco Nexus: Industry standard for data centers
- vPC: Mature, widely deployed technology
- HSRP: Battle-tested failover protocol

**4. Expert Team**
- Experienced network engineers
- Vendor support on standby
- Detailed runbooks and procedures

**5. Comprehensive Rollback**
- Per-phase rollback procedures documented
- Configuration backups at every step
- Can restore old environment if needed

---

## Slide 6: Timeline & Schedule

### Project Timeline

```
Week 1-2: Planning & Preparation
├─ Hardware procurement/delivery
├─ Configuration development
└─ Testing & validation
                                    [We Are Here]
                                         ↓
Week 3: Pre-Installation
├─ Physical rack installation
├─ Management network setup
└─ Layer 2 trunk establishment
    (4-6 hours, zero impact)

Week 4: MAINTENANCE WINDOW ⭐
├─ Saturday Evening: 6:00 PM - 2:00 AM
├─ L3 migration (WAN, routing, gateways)
└─ Expected: 1-5 second impact

Week 5-7: Device Migration
├─ Incremental moves (non-critical first)
├─ Business hours acceptable
└─ 30-60 seconds per device

Week 8: Cleanup & Closure
├─ Decommission old equipment
└─ Final documentation
```

### Critical Path: Saturday Maintenance Window

**Maintenance Window Details:**
- **Date:** Saturday, [DATE] TBD
- **Start:** 6:00 PM
- **Expected End:** ~2:00 AM (8 hours)
- **Window:** 10-12 hours (buffer included)
- **Impact:** 1-5 seconds during gateway cutover (~8:30 PM)
- **Rollback:** Possible until 72 hours post-completion

---

## Slide 7: Expected Downtime

### Service Impact Analysis

**Phase 3: L3 Migration (Saturday Evening)**

| Service | Expected Impact | Duration | Mitigation |
|---------|----------------|----------|------------|
| **Internet Access** | None | 0 sec | Secondary path during migration |
| **AVPN (MPLS)** | Brief convergence | 10-20 sec | OSPF fast reconvergence |
| **SD-WAN** | Brief outage | 5-10 min | Per-router migration (2 total) |
| **Gateway Cutover** | **Brief interruption** | **1-5 sec** | **HSRP activation (critical moment)** |
| **Wireless** | None (post-cutover) | 0 sec | Controllers reconnect automatically |
| **Servers/Apps** | Brief reconnect | 1-5 sec | ARP/MAC re-learning |

**Total Expected Downtime: < 5 seconds for most services**

**Phase 4: Device Migration**
- Per-device impact: 30-60 seconds
- Scheduled during business hours
- Non-critical devices first
- HA pairs migrated one at a time

---

## Slide 8: Success Criteria

### How We Measure Success

**Technical Metrics:**
- [ ] All routing protocols operational (OSPF: 4 adjacencies, BGP: 2 sessions)
- [ ] All WAN connectivity migrated to new infrastructure
- [ ] Gateway failover (HSRP) functioning correctly
- [ ] Zero packet loss (except during planned cutover)
- [ ] Performance meets or exceeds baseline

**Business Metrics:**
- [ ] Downtime within acceptable limits (< 5 seconds)
- [ ] No critical application outages
- [ ] No user complaints post-migration
- [ ] Project completed within timeline
- [ ] Budget maintained (no overruns)

**Operational Metrics:**
- [ ] 72-hour stability period completed
- [ ] Monitoring confirms system health
- [ ] Documentation updated
- [ ] Team trained on new platform
- [ ] Lessons learned documented

---

## Slide 9: What Could Go Wrong?

### Risk Assessment & Mitigation

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| **OSPF adjacency fails** | Low | High | Test authentication, have AVPN team on bridge |
| **BGP session doesn't establish** | Low | High | SD-WAN team validates, rollback procedure ready |
| **HSRP flapping** | Low | Medium | Pre-test configurations, monitor continuously |
| **STP loop** | Medium | High | Validate topology at each step, BPDU guard enabled |
| **Device incompatibility** | Low | Medium | Pre-identify devices, test representative samples |
| **Configuration error** | Medium | Medium | Peer review, offline validation, staging tests |
| **Extended downtime** | Low | High | 12-hour window (8 hours expected), rollback plan ready |
| **Post-migration instability** | Low | Medium | 72-hour monitoring, team on-call, quick rollback |

**Overall Risk Level: MEDIUM (Well-Managed)**

---

## Slide 10: Rollback Strategy

### If Things Go Wrong

**During L3 Migration (Phase 3):**

**Rollback Capability at Each Step:**
- **Step-by-Step Rollback:** Each WAN circuit move is reversible
- **Before Gateway Cutover:** Can abort entirely, zero impact
- **After Gateway Cutover:** 72-hour rollback window available

**Rollback Procedure (If Critical Issue):**
1. Shutdown new core switch SVIs
2. Re-enable old 3850 SVIs and routing
3. Reconnect WAN uplinks to old 3850
4. Devices automatically fail back (< 30 seconds)
5. New infrastructure remains for retry

**Recovery Time: < 5 minutes**

**After 72 Hours:**
- Commit point reached
- Old equipment no longer in routing path
- Rollback requires full re-migration (not recommended)

---

## Slide 11: Team & Resources

### Who Is Involved

**Network Engineering Team:**
- Lead Engineer (Decision maker)
- Core Switch Engineer (New Nexus)
- Legacy Switch Engineer (Old 3850)
- Validation Engineer (Testing)
- Scribe (Documentation)

**Support Teams:**
- **Vendor Support:** Cisco TAC (on standby)
- **WAN Team:** AVPN provider support
- **SD-WAN Team:** Viptela/Velocloud team
- **NOC:** 24/7 monitoring and alerting
- **Application Teams:** On-call for validation

**External Dependencies:**
- **AT&T:** AVPN/Internet circuits (no changes required)
- **Colocation Provider:** Power, cooling (verified sufficient)

**Communication:**
- Conference bridge for entire team
- Chat channel for real-time updates
- Status page for stakeholder visibility

---

## Slide 12: Cost & Budget

### Financial Overview

**Capital Expenses (CapEx):**
| Item | Quantity | Unit Cost | Total |
|------|----------|-----------|-------|
| Nexus Core (N9K-C93240YC-FX2) | 2 | $XX,XXX | $XXX,XXX |
| Nexus Fiber Access (N9K-C93180YC-FX3) | 2 | $XX,XXX | $XXX,XXX |
| Nexus Copper Access (N9K-C93108TC-FX3) | 2 | $XX,XXX | $XXX,XXX |
| Optics/Transceivers | ~50 | $XXX | $XX,XXX |
| Cables/Hardware | - | - | $X,XXX |
| Opengear Console Server | 1 | $X,XXX | $X,XXX |
| **Total CapEx** | | | **$XXX,XXX** |

**Operational Expenses (OpEx):**
| Item | Annual Cost |
|------|-------------|
| Smartnet Support (6 switches) | $XX,XXX |
| Software licenses | $X,XXX |
| Training | $X,XXX |
| **Total OpEx (Annual)** | **$XX,XXX** |

**ROI Considerations:**
- Avoids compliance risk (end-of-life)
- Enables revenue-generating projects (SD-WAN, DNA Center)
- Reduces operational complexity
- Eliminates 4 ToR switches (saves support costs)

---

## Slide 13: Dependencies & Prerequisites

### What Must Be in Place

**Before Phase 1 (Preparation):**
- [ ] Hardware delivered and verified
- [ ] Rack space confirmed available
- [ ] Power circuits verified (dual A+B)
- [ ] Change request approved
- [ ] Team training completed

**Before Phase 3 (Maintenance Window):**
- [ ] Phase 1 & 2 completed successfully
- [ ] All configurations peer-reviewed
- [ ] Maintenance window scheduled and approved
- [ ] Stakeholders notified (3 weeks advance)
- [ ] Rollback procedures tested
- [ ] Team assignments confirmed
- [ ] Conference bridge tested
- [ ] Vendor support on standby

**During Maintenance Window:**
- [ ] All team members present
- [ ] No other changes in freeze period
- [ ] NOC monitoring active
- [ ] Status page ready for updates

---

## Slide 14: Communication Plan

### Keeping Stakeholders Informed

**Pre-Migration (3 Weeks Before):**
- Email notification to all stakeholders
- Change request published (CAB approval)
- Status page announcement
- Team briefings scheduled

**1 Week Before:**
- Reminder notification sent
- Final team preparation meeting
- Go/No-Go decision checkpoint

**Day Before:**
- Final reminder to stakeholders
- Confirm all prerequisites met
- Team final briefing

**During Maintenance:**
- Status page: "Maintenance In Progress"
- Email updates at key milestones:
  - Start (6:00 PM)
  - Gateway cutover (8:30 PM)
  - Completion (~2:00 AM)
- Bridge open for questions

**Post-Migration:**
- Success notification sent (within 1 hour)
- Status page: "Maintenance Complete"
- Daily status reports (72 hours)
- Lessons learned session (1 week)
- Final project closure report (2 weeks)

---

## Slide 15: Post-Migration Plan

### After Maintenance Window

**Immediate (0-24 Hours):**
- Monitoring: Continuous log review
- Team: On-call for issues
- Status: Daily reports to management
- Validation: Performance baseline

**Short-Term (Week 1):**
- Phase 4 planning begins (device migration)
- Documentation updates
- Monitoring threshold adjustments
- Configuration audit

**Medium-Term (Weeks 2-7):**
- Device migration execution
- Incremental moves during business hours
- VxRail ToR consolidation
- User training on any changes

**Long-Term (Week 8+):**
- Old equipment decommissioning
- Final cost reconciliation
- Lessons learned documentation
- Singapore site planning (repeat process)

**Ongoing:**
- Monthly performance reports
- Quarterly capacity reviews
- Annual technology refresh planning

---

## Slide 16: Lessons from Similar Projects

### Industry Best Practices Applied

**What We Learned from Previous Migrations:**

**1. Parallel Operation is Critical**
- Running old and new side-by-side reduces risk
- Layer 2 trunk provides safety net
- Easy rollback if issues arise

**2. Incremental Validation Saves Time**
- Test after each step before proceeding
- Small issues caught early, easy to fix
- Prevents cascading failures

**3. Team Communication is Key**
- Dedicated conference bridge prevents confusion
- Clear role assignments reduce errors
- Scribe documentation invaluable for post-mortem

**4. Conservative Timeline Reduces Stress**
- 10-12 hour window for 6-8 hour work
- Buffer time for unexpected issues
- Team not rushed, fewer mistakes

**5. Stakeholder Communication Prevents Panic**
- Advance notice sets expectations
- Real-time updates reduce anxiety
- Transparent reporting builds trust

---

## Slide 17: Why This Approach Works

### Technical Validation

**Industry-Proven Design:**
- Cisco Nexus vPC: Deployed in thousands of data centers
- HSRP: 20+ years of production use
- Phased migration: Recommended by Cisco best practices

**Our Specific Advantages:**
- Experienced team (10+ years Cisco networking)
- Detailed planning (3+ months preparation)
- Vendor support (Cisco TAC on standby)
- Lab testing (validated in staging environment)
- Conservative estimates (built-in buffer time)

**Risk Mitigation Layers:**
1. Offline configuration and testing
2. Parallel operation during migration
3. Step-by-step validation
4. Go/No-Go decision points
5. Comprehensive rollback procedures
6. 72-hour monitoring period
7. Vendor support availability

**Success Probability: 95%+ (Based on similar projects)**

---

## Slide 18: What We Need from Management

### Approvals & Support Required

**Approvals Needed:**
- [ ] Change request approval (CAB)
- [ ] Maintenance window authorization (Saturday evening)
- [ ] Budget approval ($XXX,XXX CapEx)
- [ ] Resource allocation (team overtime compensation)
- [ ] Communication authorization (stakeholder notifications)

**Support Requested:**
- **Communication:** Help notify business stakeholders
- **Flexibility:** Accept 1-5 second impact during cutover
- **Patience:** Allow 72-hour monitoring before declaring success
- **Trust:** Empower team to make technical decisions during migration
- **Recognition:** Acknowledge team effort post-completion

**What We Commit To:**
- Minimize downtime (< 5 seconds target)
- Complete within timeline (8 hours)
- Maintain within budget
- Daily status updates
- Immediate escalation if issues arise
- Comprehensive documentation
- Successful project completion

---

## Slide 19: Next Steps

### Action Items - Next 2 Weeks

**This Week:**
- [ ] Management approval (today's meeting)
- [ ] Schedule maintenance window (Saturday, [DATE])
- [ ] Finalize HSRP IP allocation
- [ ] Complete configuration peer review
- [ ] Order any remaining hardware/cables

**Next Week:**
- [ ] Submit change request to CAB
- [ ] Send initial stakeholder notification (3 weeks advance)
- [ ] Begin Phase 1 (offline configuration)
- [ ] Schedule team training sessions
- [ ] Confirm vendor support availability

**Week Before Maintenance:**
- [ ] Complete Phase 2 (physical installation)
- [ ] Final team briefing
- [ ] Send reminder notification to stakeholders
- [ ] Conduct final Go/No-Go checkpoint
- [ ] Verify all prerequisites met

**Maintenance Day:**
- [ ] Team assembly (5:00 PM)
- [ ] Final system checks (6:00 PM start)
- [ ] Execute Phase 3 (L3 migration)
- [ ] Post-completion reporting

---

## Slide 20: Questions & Discussion

### Open Floor

**Common Questions Anticipated:**

**Q: What if the migration takes longer than 8 hours?**
A: We have a 10-12 hour window. If extending beyond, we have abort procedures and can rollback.

**Q: Can we do this during business hours?**
A: No. Critical infrastructure changes require off-hours window. Saturday evening minimizes business impact.

**Q: What about Singapore site?**
A: Amsterdam is first. After 2-4 weeks validation, we'll replicate process in Singapore using lessons learned.

**Q: What if a critical issue is found post-migration?**
A: 72-hour rollback window. We can revert to old infrastructure if needed within 3 days.

**Q: How confident are you in success?**
A: 95%+ confidence. Proven technology, experienced team, detailed planning, vendor support, comprehensive testing.

**Q: What's the worst-case scenario?**
A: Extended outage (rollback required). Mitigated by: Conservative timeline, rollback procedures, expert team, vendor support.

**Q: How will this affect end users?**
A: Minimal. 1-5 second interruption during gateway cutover. Most users won't notice. No application downtime expected.

---

## Slide 21: Recommendation

### Management Decision Required

**We Recommend: PROCEED with Migration**

**Justification:**
1. **Risk is Acceptable:** Well-planned, proven technology, expert team
2. **Timing is Right:** Hardware end-of-life forces action now
3. **Business Value:** Enables future initiatives (SD-WAN, DNA Center)
4. **Cost is Justified:** Avoids compliance risk, increases capacity
5. **Team is Ready:** Detailed planning complete, confidence high

**Alternatives Considered:**
- **Do Nothing:** NOT VIABLE (end-of-life, compliance risk, capacity exhausted)
- **Incremental Upgrade:** NOT POSSIBLE (platform limitations)
- **Forklift Replacement:** HIGHER RISK (no parallel operation)
- **Defer to Later:** INCREASES RISK (aging hardware, rushed timeline)

**Recommended Maintenance Window:**
- **Date:** Saturday, [DATE] TBD
- **Time:** 6:00 PM - 6:00 AM
- **Expected Duration:** 6-8 hours
- **Expected Impact:** < 5 seconds

**Seeking Approval To:**
- Proceed with migration plan
- Schedule maintenance window
- Allocate team resources (overtime)
- Notify stakeholders (3 weeks advance)

---

## Slide 22: Summary

### Key Takeaways

**The Plan:**
- Migrate from legacy 3850 stack to modern Nexus vPC architecture
- "L3 First, Cables Last" approach minimizes risk
- Saturday evening maintenance window (8 hours)
- Expected impact: 1-5 seconds during gateway cutover

**The Benefits:**
- 2x port capacity, active-active forwarding
- Eliminates single point of failure
- Enables future initiatives
- Modern platform for 5+ years

**The Risks:**
- Well-managed through detailed planning
- Comprehensive rollback procedures
- 72-hour safety window
- Expert team and vendor support

**The Ask:**
- Approve migration plan
- Authorize maintenance window
- Support team during execution
- Trust technical expertise

**The Commitment:**
- Minimize downtime (< 5 seconds)
- Complete within timeline
- Maintain communication
- Ensure successful outcome

---

## Appendix: Technical Details

### For Technical Stakeholders

**Current Environment:**
- 6x Catalyst 3850 stack (AMIDCnsm0101)
- 48x 10G SFP+ (100% utilized)
- 192x 1G PoE
- OSPF: 4 adjacencies (AT&T AVPN)
- BGP: 2 sessions (SD-WAN, 692 prefixes each)
- 50+ production VLANs
- ~100 static routes

**Target Environment:**
- 2x N9K-C93240YC-FX2 (cores)
- 2x N9K-C93180YC-FX3 (fiber access)
- 2x N9K-C93108TC-FX3 (copper access)
- vPC domains: 101 (core), 102 (copper), 103 (fiber)
- HSRP for gateway redundancy
- Same OSPF/BGP topology (routes preserved)
- Eliminates 4x ToR switches

**Migration Phases:**
1. Pre-Migration: Offline config (2-3 days)
2. Installation: Physical setup (4-6 hours, zero impact)
3. L3 Migration: Saturday evening (6-8 hours, < 5 sec impact)
4. Device Migration: Incremental (weeks, 30-60 sec per device)
5. Decommission: Cleanup (1 day, zero impact)

---

**QUESTIONS?**

**Contact Information:**
- Project Lead: [Name] - [Email] - [Phone]
- Network Manager: [Name] - [Email] - [Phone]
- Change Management: [Email]

**Thank you for your time and consideration.**
