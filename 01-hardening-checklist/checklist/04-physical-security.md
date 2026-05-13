# Physical Security Checklist

This checklist defines a physical security baseline for internet cafes, gaming venues, esports hotels, and managed shared-PC environments. It is written for venues where customers can physically reach client PCs, desks, cables, peripherals, wall ports, and sometimes staff areas during busy operations.

Physical controls do not replace Windows hardening, network isolation, logging, or incident response. They reduce the likelihood that an attacker can bypass those controls by touching the hardware, boot chain, removable media path, network port, or evidence source.

This checklist assumes the threat model in [`00-threat-model.md`](00-threat-model.md), the Windows host baseline in [`01-windows-host.md`](01-windows-host.md), the billing software baseline in [`02-billing-software.md`](02-billing-software.md), and the network isolation baseline in [`03-network-isolation.md`](03-network-isolation.md).

## Threat Background

Customer-facing venues have a physical access problem by design. A client PC may be locked down in software while still exposing USB ports, display cables, network jacks, boot options, removable drives, or chassis panels. A cashier workstation may have strong passwords but still be visible from the counter. A server may be segmented on the network but left in an unlocked cabinet.

Relevant ATT&CK techniques include T1200 Hardware Additions, T1091 Replication Through Removable Media, T1052 Exfiltration Over Physical Medium, T1542 Pre-OS Boot, T1552 Unsecured Credentials, T1078 Valid Accounts, T1021 Remote Services, T1046 Network Service Discovery, T1562 Impair Defenses, and T1486 Data Encrypted for Impact.

The defensive objective is not to create airport-grade physical security. The objective is to make tampering harder, make tampering visible, protect the billing authority, preserve evidence, and avoid physical layouts that defeat otherwise good technical controls.

## Physical Zones

| Zone | Examples | Baseline Trust Level | Minimum Controls |
| --- | --- | --- | --- |
| Public customer area | Gaming desks, client PCs, peripherals, public charging areas | Untrusted | Locked chassis, blocked unused ports, visible staff patrol, camera coverage where lawful, disabled unused wall jacks. |
| Cashier and reception | Cashier workstation, payment terminal, receipt printer, cash drawer | Semi-trusted | Screen privacy, cable control, staff-only access, camera coverage focused on transaction area, no customer reach to admin ports. |
| Server and network area | Billing server, database host, switches, firewall, NAS, UPS | High trust | Locked cabinet or room, access log, camera coverage, environmental monitoring, restricted keys. |
| Build and repair area | Golden image host, spare disks, repair bench, boot media | High trust | Restricted staff access, media inventory, hash records, chain of custody for removed disks. |
| CCTV and evidence area | NVR, camera controller, log collector, backup device | High trust | Restricted access, time sync, tamper-evident storage, separate credentials. |
| Guest and vendor area | Waiting area, vendor workbench, temporary support laptop | Untrusted until approved | Escort policy, quarantine network, no direct access to billing or management networks. |

## Checklist

### Asset Control and Physical Access

- [ ] **PS-01: Maintain a physical asset inventory for all business-critical devices.**
  - Risk: Unknown or untracked devices make theft, substitution, repair loss, and incident response harder.
  - Recommended configuration: Record asset tag, serial number, host role, location, owner, network zone, disk encryption state, warranty status, and disposal status for client PCs, servers, cashier workstations, switches, firewalls, APs, NVRs, NAS devices, and backup media.
  - Verification: Walk the venue with the inventory and reconcile every device. Investigate any device on the floor or network that is not in the inventory.
  - References: NIST CSF 2.0 ID.AM, NIST SP 800-53 CM-8 and PE controls.

- [ ] **PS-02: Keep billing servers, network equipment, backups, and log collectors in a locked room or cabinet.**
  - Risk: Direct access to servers, switches, firewalls, NAS devices, or backup drives can bypass network and account controls.
  - Recommended configuration: Use a locked rack, cabinet, or room for the billing server, database host, firewall, core switch, backup storage, log collector, and NVR. Limit access to named staff and approved contractors.
  - Verification: Confirm the equipment is physically locked during business hours and after hours. Review access list, key custody, and recent maintenance entries.
  - References: NIST SP 800-53 PE-2, PE-3, and PE-6; CIS Controls v8.1 Control 1.

- [ ] **PS-03: Physically secure cashier and manager workstations.**
  - Risk: A customer or visitor who reaches the cashier PC can attach devices, view screens, disconnect cables, or attempt local access.
  - Recommended configuration: Place cashier and manager workstations behind staff-only boundaries. Use cable locks or secured mounts for small systems. Keep USB ports, network ports, and power controls out of customer reach.
  - Verification: Stand at the customer side of the counter and confirm the keyboard, mouse, USB ports, power button, network cable, and display cable cannot be reached without staff crossing.
  - References: NIST SP 800-53 PE-3 and PE-18, MITRE ATT&CK T1200.

- [ ] **PS-04: Lock or seal client PC chassis.**
  - Risk: Opening a chassis can allow disk removal, hardware implants, CMOS reset attempts, boot device changes, or disconnection of security components.
  - Recommended configuration: Use chassis locks, locked enclosures, tamper-evident seals, or mounting designs that prevent casual access to side panels and internal drives.
  - Verification: Inspect a sample of client PCs weekly and confirm panels are closed, locks are intact, and seal IDs match the maintenance log.
  - References: MITRE ATT&CK T1200 and T1052, NIST SP 800-53 PE-3.

- [ ] **PS-05: Use tamper-evident seals for high-risk components.**
  - Risk: Small hardware changes may not be obvious during a busy shift.
  - Recommended configuration: Apply numbered tamper-evident seals to client chassis, server drive bays, network cabinets, backup cases, and critical cable panels. Record seal IDs and replacement reasons.
  - Verification: Compare seal IDs during monthly audits and after any incident, repair, or vendor visit.
  - References: NIST SP 800-53 PE-3 and SI-7, MITRE ATT&CK T1200.

- [ ] **PS-06: Control physical keys, rack keys, cabinet keys, and spare device access.**
  - Risk: Lost or shared keys create unlogged physical access to systems that hold billing and evidence.
  - Recommended configuration: Maintain a key register with named custodians. Store spare keys in a controlled location. Rotate locks or recover keys after staff departure or contractor changes.
  - Verification: Review the key register and perform a spot check that each key is accounted for.
  - References: NIST SP 800-53 PE-2 and PE-3.

- [ ] **PS-07: Log vendor and contractor physical access.**
  - Risk: Vendor visits, repairs, and emergency support can create undocumented changes to systems, cables, firmware, or storage.
  - Recommended configuration: Record visitor name, company, purpose, arrival and departure time, escort, systems touched, and change ticket or support case.
  - Verification: Compare visitor log entries with firewall changes, billing software changes, Windows event logs, and camera timestamps for the same period.
  - References: NIST SP 800-53 PE-2, PE-6, and CM-3.

- [ ] **PS-08: Define a controlled process for device removal and repair.**
  - Risk: Disks, PCs, and network devices removed for repair may contain credentials, logs, billing data, or customer information.
  - Recommended configuration: Require approval before removing any business-critical device. Record serial number, disk encryption state, data sanitization status, repair vendor, handoff time, and return condition.
  - Verification: Audit repair records against the asset inventory and BitLocker or encryption status.
  - References: NIST SP 800-88 media sanitization guidance, NIST SP 800-53 MP and PE controls.

- [ ] **PS-09: Keep spare systems and boot media in a restricted build area.**
  - Risk: Golden images, bootable USB drives, spare disks, and repair tools can become a privileged path into many client PCs.
  - Recommended configuration: Store boot media, image drives, spare disks, and repair laptops in a locked cabinet or staff-only build area. Label media and record hashes for golden images.
  - Verification: Reconcile boot media and spare disks monthly. Confirm each item has an owner and purpose.
  - References: NIST SP 800-128 configuration management, NIST SP 800-88, MITRE ATT&CK T1542.

### USB, External Ports, and Removable Media

- [ ] **PS-10: Block unused external USB ports on customer-facing PCs.**
  - Risk: Exposed USB ports allow removable media, rogue HID devices, network adapters, and hardware implants.
  - Recommended configuration: Use physical USB port blockers, locked cases, or desk layouts that expose only approved peripherals. Pair this with Windows removable storage and device installation policy.
  - Verification: Inspect a sample of client PCs and confirm unused front, rear, monitor, and keyboard USB hubs are blocked or inaccessible.
  - References: MITRE ATT&CK T1200 and T1091, Microsoft removable storage access policy.

- [ ] **PS-11: Use approved peripherals and prevent customer replacement.**
  - Risk: Replacing keyboards, mice, headsets, USB hubs, or adapters can introduce rogue input devices or storage.
  - Recommended configuration: Use approved venue peripherals, cable retention, desk cable routing, and staff checks after high-risk sessions. Keep spares under staff control.
  - Verification: Compare connected peripherals against the asset or approved model list. Investigate unknown HID, storage, network, or serial devices.
  - References: MITRE ATT&CK T1200, NIST SP 800-53 CM-8.

- [ ] **PS-12: Provide separate public charging, not charging from business PCs.**
  - Risk: Customers may plug phones or unknown devices into client PCs or cashier systems for charging, creating device and data exposure.
  - Recommended configuration: Provide dedicated charging stations or power-only charging cables separate from venue PCs. Do not allow phone charging from cashier, server, or management devices.
  - Verification: Walk the customer and cashier areas and confirm charging options do not require connecting to business PCs.
  - References: NIST SP 800-53 PE-18, MITRE ATT&CK T1200.

- [ ] **PS-13: Inspect for unknown USB, video, and network adapters during shift checks.**
  - Risk: Small adapters can be left behind to capture input, bridge networks, or provide unauthorized connectivity.
  - Recommended configuration: Train staff to look for unexpected USB sticks, inline keyboard adapters, HDMI/DisplayPort capture devices, small Ethernet bridges, and unauthorized wireless dongles.
  - Verification: Add adapter inspection to opening or closing checklists and record exceptions.
  - References: MITRE ATT&CK T1200 and T1052.

- [ ] **PS-14: Disable or physically restrict Thunderbolt, USB4, and high-risk expansion ports where not required.**
  - Risk: High-speed external ports can expose DMA and device-attachment risks on systems that do not need them.
  - Recommended configuration: Disable unused Thunderbolt or USB4 ports in firmware or management policy where feasible. Use Kernel DMA Protection and modern platform security on systems that require these ports.
  - Verification: Review firmware settings, Windows Security device security status, and `System Information` for Kernel DMA Protection state on supported Windows systems.
  - References: Microsoft Kernel DMA Protection, Microsoft Secured-core PC guidance, MITRE ATT&CK T1200.

- [ ] **PS-15: Control staff removable media with an approval and scanning process.**
  - Risk: Staff USB drives can move malware, scripts, or customer data between home, vendor, and venue systems.
  - Recommended configuration: Require approval for staff removable media, scan media before use, restrict use to admin or build systems, and prohibit copying billing exports to unmanaged drives.
  - Verification: Review removable media exceptions, Defender or EDR logs, and file transfer records.
  - References: MITRE ATT&CK T1091 and T1052, NIST SP 800-53 MP-7.

### Firmware, Boot Chain, TPM, and Disk Protection

- [ ] **PS-16: Set UEFI or BIOS administrator passwords on client, cashier, server, and build systems.**
  - Risk: Without firmware passwords, a person with physical access may change boot order, disable Secure Boot, enable external boot, or alter device settings.
  - Recommended configuration: Set unique or managed firmware administrator passwords by host role. Store them in a controlled password vault, not in repair notes or chat messages.
  - Verification: During maintenance, attempt to enter firmware setup on a sample system and confirm administrator authentication is required.
  - References: NIST SP 800-147 BIOS protection guidance, NIST SP 800-53 IA-5 and PE-3.

- [ ] **PS-17: Lock boot order to the approved internal disk or managed network boot path.**
  - Risk: Alternate boot media can bypass Windows controls and access local disks, credentials, or configuration.
  - Recommended configuration: Disable USB, optical, and unapproved PXE boot on production systems. Allow network boot only for controlled imaging workflows.
  - Verification: Inspect UEFI boot order during maintenance and attempt a controlled boot from a known USB device on a test system to confirm it is blocked.
  - References: NIST SP 800-147, MITRE ATT&CK T1542 Pre-OS Boot.

- [ ] **PS-18: Enable Secure Boot on supported systems.**
  - Risk: Unsigned or unauthorized boot components weaken OS integrity and can enable pre-OS tampering.
  - Recommended configuration: Enable Secure Boot with approved keys on Windows client, cashier, server, and build systems unless a documented hardware or driver exception exists.
  - Verification: Run `Confirm-SecureBootUEFI` on supported Windows systems and record exceptions.
  - References: Microsoft Secure Boot documentation, NIST SP 800-193 platform firmware resiliency.

- [ ] **PS-19: Keep TPM enabled and healthy for systems that protect sensitive data.**
  - Risk: Without a healthy TPM, disk encryption and device integrity features may be weaker or harder to manage.
  - Recommended configuration: Enable TPM 2.0 where supported for cashier, manager, server, build, and modern client systems. Document devices that cannot support TPM-backed protection.
  - Verification: Run `Get-Tpm` and review `TpmPresent`, `TpmReady`, and `ManagedAuthLevel`.
  - References: Microsoft TPM recommendations, NIST SP 800-193.

- [ ] **PS-20: Use BitLocker on high-value and mobile systems.**
  - Risk: Removed disks, stolen workstations, and repair handling can expose billing records, credentials, logs, and configuration.
  - Recommended configuration: Enable BitLocker for billing servers, cashier workstations, manager laptops, build systems, and backup-control hosts. Escrow recovery keys securely.
  - Verification: Run `Get-BitLockerVolume` or `manage-bde -status` and confirm protection is enabled.
  - References: Microsoft BitLocker documentation, NIST SP 800-111 storage encryption guidance.

- [ ] **PS-21: Consider pre-boot authentication for systems with high theft or insider risk.**
  - Risk: TPM-only encryption may not be enough when an attacker can steal a powered-off device and attempt offline or hardware-assisted attacks.
  - Recommended configuration: Evaluate TPM plus PIN or equivalent pre-boot controls for manager laptops, build systems, and servers in less controlled locations. Balance this against unattended restart requirements.
  - Verification: Review BitLocker protector type with `manage-bde -protectors -get C:` and confirm the documented model matches operational needs.
  - References: Microsoft BitLocker countermeasures, NIST SP 800-111.

- [ ] **PS-22: Disable legacy boot and compatibility support modules where feasible.**
  - Risk: Legacy boot paths may bypass Secure Boot and modern platform protections.
  - Recommended configuration: Use UEFI-only boot on supported systems. Disable CSM or legacy boot unless a documented hardware dependency exists.
  - Verification: Review firmware boot mode and Windows `System Information` for BIOS Mode.
  - References: Microsoft Secure Boot documentation, NIST SP 800-147.

- [ ] **PS-23: Update firmware through an authenticated and tracked process.**
  - Risk: Outdated firmware can contain security vulnerabilities, while uncontrolled firmware updates can break boot or platform protections.
  - Recommended configuration: Track firmware versions for servers, cashier systems, client PCs, switches, firewalls, APs, and storage. Apply vendor-signed firmware updates through a maintenance process with rollback planning.
  - Verification: Compare current firmware versions against vendor release notes and update records.
  - References: NIST SP 800-193, NIST SP 800-128.

- [ ] **PS-24: Protect recovery media, imaging tools, and vendor service tools.**
  - Risk: Bootable repair media can reset passwords, change disks, disable controls, or expose golden images.
  - Recommended configuration: Store recovery media and imaging tools in a locked location. Label each item, record hash or version where applicable, and restrict use to approved staff.
  - Verification: Reconcile media inventory monthly and after each repair or imaging event.
  - References: NIST SP 800-88, NIST SP 800-128, MITRE ATT&CK T1542.

### Network Physical Protection

- [ ] **PS-25: Lock patch panels, switches, firewalls, and ISP equipment.**
  - Risk: Physical access to network gear can bypass VLAN design, mirror traffic, reset devices, or attach unauthorized systems.
  - Recommended configuration: Keep network equipment in locked racks or rooms. Limit access to named staff and approved contractors.
  - Verification: Inspect network closets and cabinets during opening and closing checks. Confirm locks, seals, and access records are intact.
  - References: NIST SP 800-53 PE-3, CIS Controls v8.1 Control 12.

- [ ] **PS-26: Disable unused switch ports and unused wall jacks.**
  - Risk: Open ports let customers, vendors, or visitors attach unauthorized laptops, bridges, or rogue access points.
  - Recommended configuration: Administratively disable unused ports. Document live wall jacks and map them to switch ports and VLANs.
  - Verification: Compare switch port status with the physical port map. Test a spare wall jack and confirm it is disabled or placed in quarantine.
  - References: CIS Controls v8.1 Control 12, MITRE ATT&CK T1046.

- [ ] **PS-27: Protect exposed Ethernet cabling and desk ports.**
  - Risk: Accessible cables can be unplugged, moved to another device, tapped, or connected through mini-switches.
  - Recommended configuration: Use locked floor boxes, cable trays, strain relief, desk grommets, and tamper-evident labels for client and cashier network cables.
  - Verification: Walk aisles and desks to confirm cables cannot be casually unplugged or rerouted without staff noticing.
  - References: NIST SP 800-53 PE-4 and PE-9, MITRE ATT&CK T1200.

- [ ] **PS-28: Separate public-facing network ports from management ports.**
  - Risk: A mislabeled or exposed management port can give an attacker access to switch, firewall, camera, or server management networks.
  - Recommended configuration: Keep management ports inside locked areas. Do not place management VLAN access on public wall jacks or customer desks.
  - Verification: Review switch configuration for access ports in the management VLAN and physically inspect where those ports terminate.
  - References: NIST SP 800-41, CIS Controls v8.1 Control 12.

- [ ] **PS-29: Use port security, 802.1X, MAC limits, or NAC where operationally feasible.**
  - Risk: Physical access to a live Ethernet port can bypass Wi-Fi and endpoint admission assumptions.
  - Recommended configuration: Apply MAC limits or 802.1X for high-risk areas. At minimum, alert on new MAC addresses appearing on cashier, server, and management ports.
  - Verification: Review switch MAC address tables and port-security events. Test an unauthorized device on a spare port in a maintenance window.
  - References: CIS Controls v8.1 Control 12, NIST SP 800-207.

- [ ] **PS-30: Protect CCTV, printer, and IoT cabling from public tampering.**
  - Risk: Cameras, printers, and IoT devices can become network pivots or blind spots if unplugged, reset, or bridged.
  - Recommended configuration: Route CCTV and IoT cabling away from customer reach, use locked NVR placement, and separate these devices from billing and cashier networks.
  - Verification: Inspect camera, printer, and NVR cabling. Confirm devices are on the intended VLAN and cannot reach billing database ports.
  - References: NISTIR 8259, MITRE ATT&CK T1200 and T1046.

### Camera Coverage, Privacy, and Evidence

- [ ] **PS-31: Cover entrances, exits, cashier counter, server cabinet, and main client aisles with cameras where lawful.**
  - Risk: Without camera coverage, physical tampering, theft, and disputed cashier interactions are harder to investigate.
  - Recommended configuration: Place cameras to capture movement around entrances, exits, cashier counter, server or network cabinet, and high-traffic client aisles. Avoid overly invasive angles.
  - Verification: Review camera views during day and night lighting conditions. Confirm key areas are visible without relying on a single camera.
  - References: NIST SP 800-53 PE-6, PE-9, and AU evidence principles.

- [ ] **PS-32: Avoid recording sensitive screen content, payment keypad input, or private areas.**
  - Risk: Poor camera placement can create privacy, payment, and customer-trust problems.
  - Recommended configuration: Aim cameras at physical movement and transaction context rather than close-up screen text, customer credentials, payment PIN pads, or private spaces. Validate Dubai or UAE legal requirements with qualified counsel.
  - Verification: Review camera footage and confirm it does not routinely capture passwords, payment card data, payment PIN entry, or private areas.
  - References: NIST Privacy Framework, PCI DSS awareness for payment environments, local legal review.

- [ ] **PS-33: Synchronize CCTV and NVR time with the same time source used by Windows and network logs.**
  - Risk: Unsynchronized video timestamps make it difficult to correlate footage with billing logs, firewall logs, and Windows event logs.
  - Recommended configuration: Configure NVRs, camera controllers, and recording systems to use approved NTP sources.
  - Verification: Compare NVR time with `w32tm /query /status` output from Windows hosts and firewall time.
  - References: NIST SP 800-92, Microsoft Windows Time service guidance.

- [ ] **PS-34: Restrict access to camera systems and recorded footage.**
  - Risk: Camera footage can reveal customer behavior, staff routines, payment processes, and incident evidence.
  - Recommended configuration: Use named camera-system accounts, strong passwords, role-based access, audit logs, and restricted export permissions. Do not share NVR admin credentials.
  - Verification: Review NVR user accounts, last-login logs, export logs, and firmware version.
  - References: NIST SP 800-53 AC-2, AC-6, AU-9, and PE-6.

- [ ] **PS-35: Define camera retention, signage, and footage export procedures.**
  - Risk: Over-retention, under-retention, or uncontrolled exports can create legal, privacy, and evidence-integrity problems.
  - Recommended configuration: Define retention period, export approval, evidence hash procedure, storage location, and signage according to local requirements and business risk.
  - Verification: Review NVR retention settings, signage placement, footage export logs, and evidence storage records.
  - References: NIST SP 800-86 forensic guidance, NIST Privacy Framework, local legal review.

### Power, Environment, and Availability

- [ ] **PS-36: Put billing servers, firewalls, switches, and storage on UPS power.**
  - Risk: Power loss can corrupt billing data, interrupt logs, break network segmentation, and create recovery disputes.
  - Recommended configuration: Use UPS units sized for graceful shutdown or short outages. Monitor battery health and replace batteries on schedule.
  - Verification: Review UPS load, runtime estimates, battery test results, and shutdown configuration.
  - References: NIST SP 800-53 PE-11 and CP controls, NIST SP 800-34.

- [ ] **PS-37: Protect server and network areas from heat, dust, and casual storage.**
  - Risk: Poor environment controls cause outages and make emergency maintenance more likely during business hours.
  - Recommended configuration: Keep racks ventilated, clean, and free of boxes, liquids, cleaning chemicals, and unrelated equipment. Maintain safe cable management.
  - Verification: Inspect racks and cabinets monthly and after renovations or layout changes.
  - References: NIST SP 800-53 PE-13, PE-14, and PE-15.

- [ ] **PS-38: Keep emergency power controls accessible to staff but not customers.**
  - Risk: Customers should not be able to power off billing or network infrastructure, but staff need safe access during electrical emergencies.
  - Recommended configuration: Place power strips, UPS controls, and emergency shutoff access in staff-controlled areas. Label critical circuits clearly for staff.
  - Verification: Walk the venue and confirm customer areas cannot casually power off critical infrastructure.
  - References: NIST SP 800-53 PE-10 and PE-11.

### Physical Incident Handling

- [ ] **PS-39: Treat broken seals, opened chassis, missing peripherals, and unknown adapters as security events.**
  - Risk: Staff may treat physical anomalies as maintenance noise and destroy evidence by rebooting or reimaging too quickly.
  - Recommended configuration: Define a physical anomaly procedure: isolate the host, photograph the state, preserve logs, notify the owner or manager, and avoid unnecessary changes before review.
  - Verification: Review the shift checklist and confirm staff know who to contact when tampering is suspected.
  - References: NIST SP 800-61 Rev. 3 incident response guidance, MITRE ATT&CK T1200.

- [ ] **PS-40: Preserve suspect removable media and hardware adapters safely.**
  - Risk: Plugging suspect devices into staff systems for curiosity can spread malware or alter evidence.
  - Recommended configuration: Place suspect devices in a labeled bag or container, record where and when they were found, and analyze only on an isolated forensic or sacrificial system.
  - Verification: Run a tabletop exercise for a found USB device or inline adapter.
  - References: NIST SP 800-86 forensic guidance, MITRE ATT&CK T1091 and T1052.

- [ ] **PS-41: Review camera footage before restoring a physically suspicious client PC.**
  - Risk: Restoration can erase local evidence and make it harder to distinguish customer tampering from normal failure.
  - Recommended configuration: If physical tampering is suspected, preserve relevant footage, Windows logs, billing logs, and device state before reimaging.
  - Verification: Confirm the incident playbook includes a pre-restore evidence checklist and footage export process.
  - References: NIST SP 800-61 Rev. 3, NIST SP 800-86.

- [ ] **PS-42: Perform scheduled physical security walk-throughs.**
  - Risk: Controls drift as desks move, ports break, staff change, and emergency fixes accumulate.
  - Recommended configuration: Conduct weekly quick checks for customer areas and monthly deeper checks for server, network, cashier, CCTV, and build areas.
  - Verification: Maintain a dated checklist with findings, owner, remediation date, and retest status.
  - References: NIST CSF 2.0 GV.OV and ID.AM, CIS Controls v8.1 Control 1.

## Minimum Validation Package

For a physical security review, collect the following evidence without exposing customer personal data:

- asset inventory with serial numbers, locations, owners, and host roles;
- photos or diagrams of locked server, network, cashier, build, and CCTV areas;
- key custody and vendor visitor logs;
- sample chassis lock or tamper-seal inspection records;
- USB and external-port control evidence for client PCs and cashier workstations;
- UEFI or BIOS password, boot order, Secure Boot, TPM, and BitLocker status evidence;
- switch port map, disabled-port list, and wall-jack map;
- camera coverage map, NVR time-sync evidence, retention settings, and access review;
- UPS and environmental inspection records;
- physical incident handling checklist and last tabletop exercise record.

## Practical Verification Commands

Use these commands on systems the venue owns or is authorized to inspect.

```powershell
# Check Secure Boot state on supported Windows systems.
Confirm-SecureBootUEFI

# Check TPM state.
Get-Tpm

# Check BitLocker protection state.
Get-BitLockerVolume
manage-bde -status

# Review time source for correlation with CCTV and firewall logs.
w32tm /query /status
w32tm /query /source

# Review connected plug-and-play devices for unexpected adapters.
pnputil /enum-devices /connected

# Review network adapters and link state.
Get-NetAdapter | Select-Object Name,InterfaceDescription,Status,MacAddress,LinkSpeed
```

## References

- CafeSec Lab threat model foundation: `00-threat-model.md`
- CafeSec Lab Windows host hardening checklist: `01-windows-host.md`
- CafeSec Lab billing software security checklist: `02-billing-software.md`
- CafeSec Lab network isolation checklist: `03-network-isolation.md`
- MITRE ATT&CK Enterprise Matrix: https://attack.mitre.org/matrices/enterprise/
- MITRE ATT&CK T1200 Hardware Additions: https://attack.mitre.org/techniques/T1200/
- MITRE ATT&CK T1091 Replication Through Removable Media: https://attack.mitre.org/techniques/T1091/
- MITRE ATT&CK T1052 Exfiltration Over Physical Medium: https://attack.mitre.org/techniques/T1052/
- MITRE ATT&CK T1542 Pre-OS Boot: https://attack.mitre.org/techniques/T1542/
- MITRE ATT&CK T1552 Unsecured Credentials: https://attack.mitre.org/techniques/T1552/
- MITRE ATT&CK T1078 Valid Accounts: https://attack.mitre.org/techniques/T1078/
- MITRE ATT&CK T1021 Remote Services: https://attack.mitre.org/techniques/T1021/
- MITRE ATT&CK T1046 Network Service Discovery: https://attack.mitre.org/techniques/T1046/
- MITRE ATT&CK T1562 Impair Defenses: https://attack.mitre.org/techniques/T1562/
- MITRE ATT&CK T1486 Data Encrypted for Impact: https://attack.mitre.org/techniques/T1486/
- NIST Cybersecurity Framework 2.0: https://www.nist.gov/cyberframework
- NIST Privacy Framework: https://www.nist.gov/privacy-framework
- NIST SP 800-53 Rev. 5, Security and Privacy Controls: https://csrc.nist.gov/Pubs/sp/800/53/r5/upd1/Final
- NIST SP 800-61 Rev. 3, Incident Response Recommendations and Considerations for Cybersecurity Risk Management: https://csrc.nist.gov/pubs/sp/800/61/r3/final
- NIST SP 800-86, Guide to Integrating Forensic Techniques into Incident Response: https://csrc.nist.gov/pubs/sp/800/86/final
- NIST SP 800-88 Rev. 1, Guidelines for Media Sanitization: https://csrc.nist.gov/pubs/sp/800/88/r1/final
- NIST SP 800-111, Guide to Storage Encryption Technologies for End User Devices: https://csrc.nist.gov/pubs/sp/800/111/final
- NIST SP 800-128, Guide for Security-Focused Configuration Management: https://csrc.nist.gov/publications/detail/sp/800-128/final
- NIST SP 800-147, BIOS Protection Guidelines: https://csrc.nist.gov/pubs/sp/800/147/final
- NIST SP 800-153, Guidelines for Securing Wireless Local Area Networks: https://csrc.nist.gov/pubs/sp/800/153/final
- NIST SP 800-193, Platform Firmware Resiliency Guidelines: https://csrc.nist.gov/pubs/sp/800/193/final
- NISTIR 8259, Foundational Cybersecurity Activities for IoT Device Manufacturers: https://csrc.nist.gov/pubs/ir/8259/final
- CIS Critical Security Controls v8.1: https://www.cisecurity.org/controls/v8-1
- Microsoft Secure Boot: https://learn.microsoft.com/windows/security/operating-system-security/system-security/secure-the-windows-boot-process
- Microsoft TPM recommendations: https://learn.microsoft.com/windows/security/hardware-security/tpm/tpm-recommendations
- Microsoft BitLocker documentation: https://learn.microsoft.com/windows/security/operating-system-security/data-protection/bitlocker/
- Microsoft BitLocker countermeasures: https://learn.microsoft.com/windows/security/operating-system-security/data-protection/bitlocker/countermeasures
- Microsoft Kernel DMA Protection: https://learn.microsoft.com/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt
- Microsoft Secured-core PCs: https://learn.microsoft.com/windows-hardware/design/device-experiences/oem-highly-secure
- Microsoft removable storage access policy: https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-removablestorage
- PCI Security Standards Council: https://www.pcisecuritystandards.org/
