import "pe"

/*
Rule intent:
This rule identifies Windows PE files that look like generic user-mode
memory scanners. In shared-PC venues, this class of binary matters because
customer-accessible systems may be targeted by tools that enumerate
processes, read process memory, compare candidate values, and then guide
manual tampering or cheating workflows.

This rule is not a signature for a specific public tool. It does not encode
tool names, vendor names, file hashes, or strings that would help someone
locate or clone a bypass. The rule combines generic API imports with generic
scan-loop and comparison language. It is designed for triage, not automatic
blocking.

Expected true positives:
1. Generic memory scanners used from customer-writable paths.
2. Debug utilities that enumerate processes and read process memory.
3. Small unsigned tools copied through removable media or downloads.
4. Proof-of-concept binaries used in authorized lab validation.
5. Unexpected utility binaries placed next to game launchers or billing agents.

Expected false positives:
1. Legitimate debuggers and profilers.
2. Anti-cheat, EDR, and IT troubleshooting tools.
3. Memory diagnostics and crash-analysis utilities.
4. Vendor support tools used during approved maintenance.
5. Internal developer utilities on build or test systems.

Operational triage:
Confirm the file path first. A match in Program Files signed by a known vendor
is less suspicious than a match in Downloads, Temp, Desktop, AppData, a USB
drive, or a writable game directory. Then check the publisher, file hash,
parent process, command line, host role, and whether billing, restoration, or
security services changed state near the same time.

Testing method:
Compile the rule with the venue's YARA engine, scan a known-good software
baseline, document false positives, then scan a controlled lab corpus. Do not
test against third-party venue systems. For production use, pair this rule with
AppLocker or WDAC telemetry, process creation logs, and billing agent health
events.

MITRE ATT&CK mapping:
- T1055 Process Injection
- T1005 Data from Local System
- T1105 Ingress Tool Transfer
- T1204 User Execution
- T1562.001 Disable or Modify Tools, when paired with service tampering

Defensive actions:
If this rule matches on a customer-facing PC, isolate the host, preserve the
binary, collect process and event logs, review camera context where lawful,
and compare the host against the known-good image. Do not publish the binary
or share it in public issues.
*/
rule CafeSec_Generic_Memory_Scanner_Behavior
{
    meta:
        description = "Detects generic memory scanning traits in Windows PE files"
        author = "CafeSec Lab Research Team"
        license = "MIT"
        date = "2026-05-13"
        status = "experimental"
        attack = "T1055,T1005,T1105,T1204"
        reference = "https://attack.mitre.org/techniques/T1055/"

    strings:
        $api_open_process = "OpenProcess" ascii wide
        $api_read_process_memory = "ReadProcessMemory" ascii wide
        $api_virtual_query_ex = "VirtualQueryEx" ascii wide
        $api_create_snapshot = "CreateToolhelp32Snapshot" ascii wide
        $api_process32_first = "Process32First" ascii wide
        $api_process32_next = "Process32Next" ascii wide

        $scan_text_1 = "exact value" ascii wide nocase
        $scan_text_2 = "increased value" ascii wide nocase
        $scan_text_3 = "decreased value" ascii wide nocase
        $scan_text_4 = "unknown initial value" ascii wide nocase

        $cmp_1 = "float" ascii wide nocase
        $cmp_2 = "double" ascii wide nocase
        $cmp_3 = "int32" ascii wide nocase
        $cmp_4 = "int64" ascii wide nocase

    condition:
        uint16(0) == 0x5a4d and
        filesize < 30MB and
        (
            pe.imports("kernel32.dll", "ReadProcessMemory") or
            $api_read_process_memory
        ) and
        (
            pe.imports("kernel32.dll", "OpenProcess") or
            $api_open_process
        ) and
        2 of ($api_virtual_query_ex, $api_create_snapshot, $api_process32_first, $api_process32_next) and
        (
            2 of ($scan_text_*) or
            3 of ($cmp_*)
        )
}
