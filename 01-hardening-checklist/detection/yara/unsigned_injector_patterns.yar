import "pe"

/*
Rule intent:
This rule identifies Windows PE files that combine generic process injection
building blocks and lack an Authenticode signature according to YARA's PE
metadata. In an internet cafe or gaming venue, such a binary is worth triage
when it appears on a customer-facing client, cashier workstation, or billing
server without an approved vendor explanation.

This rule does not describe how to inject into a process. It only looks for
defensive indicators: imports commonly needed to open a target process,
allocate memory in that process, write data, adjust memory protection, and
start execution. Many legitimate tools can use these APIs, so context matters.

Expected true positives:
1. Unauthorized utilities dropped into customer-writable paths.
2. Unsigned lab tools used for authorized security validation.
3. Loader-like binaries used to tamper with local processes.
4. Unknown support utilities that should be reviewed before production use.

Expected false positives:
1. Internal vendor support tools that are unsigned but legitimate.
2. Game anti-cheat components or launchers with unusual implementation.
3. EDR, diagnostics, debuggers, profilers, and crash handlers.
4. Installers or updaters that unpack code into another process.

Operational triage:
Check whether the file is signed through Windows tooling, because YARA's PE
signature view may vary by file type and scanner version. Review file path,
publisher, compile timestamp, hash, parent process, first-seen time, and
whether service tampering or billing anomalies occurred in the same window.

Testing method:
Scan a known-good venue baseline before production use. For false positives,
record host role, path, publisher, reason for legitimacy, and whether an
allowlist exception is acceptable. Use this rule together with Sigma rules for
process creation, service stops, and registry changes.

MITRE ATT&CK mapping:
- T1055 Process Injection
- T1105 Ingress Tool Transfer
- T1027 Obfuscated Files or Information
- T1204 User Execution
- T1562.001 Disable or Modify Tools when used against security or billing

Defensive actions:
If matched from a customer-accessible host, isolate the host, preserve the
file, collect logs, and compare against the golden image. If matched on a
server or cashier workstation, treat as at least high severity until an owner
or vendor can explain the binary.
*/
rule CafeSec_Unsigned_Process_Injection_Traits
{
    meta:
        description = "Detects unsigned PE files with generic process injection imports"
        author = "CafeSec Lab Research Team"
        license = "MIT"
        date = "2026-05-13"
        status = "experimental"
        attack = "T1055,T1105,T1027,T1204"
        reference = "https://attack.mitre.org/techniques/T1055/"

    strings:
        $api_open_process = "OpenProcess" ascii wide
        $api_virtual_alloc_ex = "VirtualAllocEx" ascii wide
        $api_write_process_memory = "WriteProcessMemory" ascii wide
        $api_virtual_protect_ex = "VirtualProtectEx" ascii wide
        $api_create_remote_thread = "CreateRemoteThread" ascii wide
        $api_nt_create_thread_ex = "NtCreateThreadEx" ascii wide
        $api_queue_user_apc = "QueueUserAPC" ascii wide
        $api_get_proc_address = "GetProcAddress" ascii wide
        $api_load_library = "LoadLibrary" ascii wide

    condition:
        uint16(0) == 0x5a4d and
        filesize < 25MB and
        not pe.is_signed and
        (
            pe.imports("kernel32.dll", "OpenProcess") or $api_open_process
        ) and
        (
            pe.imports("kernel32.dll", "WriteProcessMemory") or $api_write_process_memory
        ) and
        (
            pe.imports("kernel32.dll", "VirtualAllocEx") or $api_virtual_alloc_ex
        ) and
        1 of ($api_create_remote_thread, $api_nt_create_thread_ex, $api_queue_user_apc) and
        1 of ($api_get_proc_address, $api_load_library, $api_virtual_protect_ex)
}
