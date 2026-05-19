import "pe"
import "math"

/*
Rule intent:
This rule identifies generic packer-like traits that make Windows PE files
harder to inspect: few imports, high entropy executable sections, suspicious
section names, and runtime API resolution indicators. In a gaming venue, this
does not prove maliciousness, but it is unusual for stable billing agents,
cashier applications, and approved management utilities unless the vendor has
documented packing or protection.

This rule does not target a specific packer, product, cheat, or bypass. It
looks for traits that defenders should investigate when a binary appears in a
customer-writable path or near billing software components.

Expected true positives:
1. Packed or obfuscated unauthorized tools.
2. Dropped binaries that hide imports until runtime.
3. Unknown utilities transferred through downloads or removable media.
4. Lab samples used to validate detection and response workflow.

Expected false positives:
1. Commercial protectors used by legitimate game launchers or anti-cheat.
2. Vendor billing components protected against casual reverse engineering.
3. Installers, self-extracting archives, and compressed updaters.
4. Security tools that intentionally pack components.

Operational triage:
Do not block solely on this rule in production. First identify the host role,
path, publisher, file hash, parent process, user, and first-seen time. Ask the
vendor whether packing is expected for billing components. Compare against a
known-good software inventory and golden image hash records.

Testing method:
Scan the venue's clean baseline and classify known packed but legitimate
software. Then scan a lab corpus of benign packed software and known unwanted
tools to understand alert volume. Pair matches with WDAC/AppLocker events,
process telemetry, DNS logs, and file integrity deltas.

MITRE ATT&CK mapping:
- T1027 Obfuscated Files or Information
- T1036 Masquerading
- T1105 Ingress Tool Transfer
- T1204 User Execution

Defensive actions:
If a new packed binary appears in a customer-writable directory, quarantine the
host and preserve the file. If it appears in a billing software directory,
verify vendor signature and update records before restoring service or deleting
the file.
*/
rule CafeSec_Suspicious_Packer_Traits
{
    meta:
        description = "Detects generic PE packer traits relevant to shared-PC venue triage"
        author = "CafeSec Lab Research Team"
        license = "MIT"
        date = "2026-05-13"
        status = "experimental"
        attack = "T1027,T1036,T1105,T1204"
        reference = "https://attack.mitre.org/techniques/T1027/"

    strings:
        $runtime_api_1 = "GetProcAddress" ascii wide
        $runtime_api_2 = "LoadLibraryA" ascii wide
        $runtime_api_3 = "LoadLibraryW" ascii wide
        $runtime_api_4 = "VirtualProtect" ascii wide
        $runtime_api_5 = "VirtualAlloc" ascii wide

        $section_upx0 = "UPX0" ascii
        $section_upx1 = "UPX1" ascii
        $section_packed = ".packed" ascii
        $section_aspack = ".aspack" ascii
        $section_vmp = ".vmp" ascii

    condition:
        uint16(0) == 0x5a4d and
        filesize < 80MB and
        ((
            2 of ($runtime_api_*) and
            pe.number_of_imports < 20 and
            for any i in (0..pe.number_of_sections - 1): (
                pe.sections[i].raw_data_size > 4096 and
                math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) > 7.1
            )
        ) or
        (
            1 of ($section_*) and
            for any i in (0..pe.number_of_sections - 1): (
                pe.sections[i].name matches /UPX|packed|aspack|vmp/i
            )
        ))
}
