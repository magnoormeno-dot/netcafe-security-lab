#
# CafeSec Lab - pinned tool / image versions + checksums (reproducibility manifest).
# ------------------------------------------------------------------------------------
# WHY: detection-rule validation is only reproducible if everyone runs the SAME stack.
# Floating refs ('master', 'latest', 'Wazuh 4.x') make two builds diverge silently.
#
# HOW: download scripts (Setup-RuleEngines / Install-WazuhAgent / Deploy-Sysmon) verify a
# downloaded artifact against the Sha256 below via LabLogic\Test-LabArtifactChecksum:
#   $true  = match (proceed) | $false = mismatch/missing (STOP) | $null = no hash pinned (WARN).
#
# Sha256 fields are intentionally EMPTY until you pin them from the OFFICIAL source on first
# download (official sources only, per docs\downloads.md). Fill `Version` to the exact build
# you validated against, then record its hash. ASCII-only (parsed by tooling).
#
@{
    Sysmon = @{
        Version = '15.15'                # Sysinternals Sysmon (confirm exact on the download page)
        Sha256  = ''                     # fill after first official download of Sysmon.zip / Sysmon64.exe
        Source  = 'https://learn.microsoft.com/sysinternals/downloads/sysmon'
    }

    SysmonConfig = @{
        Repo      = 'https://github.com/SwiftOnSecurity/sysmon-config'
        # Pin to a REVIEWED commit instead of master so the baseline can't drift under you.
        PinCommit = ''                   # e.g. a 40-char commit SHA you reviewed; '' = using master (NOT reproducible)
        File      = 'sysmonconfig-export.xml'
        Sha256    = ''                   # fill after pinning a commit and downloading that revision
    }

    Wazuh = @{
        Version = '4.9'                  # pin the exact x.y.z you validate against (confirm on the release page)
        Sha256  = ''                     # agent MSI / installer hash, filled after official download
        Source  = 'https://documentation.wazuh.com/current/installation-guide/'
    }

    Yara = @{
        Version   = '4.5.5'              # VirusTotal/yara win64 release used for the committed lab evidence
        Sha256    = ''                   # yara-<ver>-win64.zip hash, filled after official download
        ExeSha256 = '1C45EB279D820ABA81FD41C22384428EBE44037CF5793BE4B52A9D3B3DF62B33'  # yara64.exe from that zip
        Source    = 'https://github.com/VirusTotal/yara/releases'
    }

    SigmaCli = @{
        # Pin sigma-cli + the opensearch backend so rule conversion is stable.
        Version = '3.0.2'                # pip install "sigma-cli==3.0.2"  (used for the committed lab evidence)
        Backend = 'opensearch'           # sigma plugin install opensearch
        # Convert with: sigma convert -t opensearch_lucene -p ecs_windows --disable-pipeline-check <rule>
        Target  = 'opensearch_lucene'
        Source  = 'https://github.com/SigmaHQ/sigma-cli'
    }

    Python = @{
        MinVersion = '3.10'
        Source     = 'https://www.python.org/downloads/windows/'
    }

    # OS images: eval ISOs expire (~180 days) and are re-spun, so a build hash + a captured
    # build label is the only way to know two people used the same media.
    Isos = @{
        Ubuntu        = @{ File = 'ubuntu-24.04-live-server-amd64.iso'; Build = '24.04.x'; Sha256 = '' }
        WinServer2022 = @{ File = 'windows-server-2022-eval.iso';        Build = '';        Sha256 = '' }
        Win11Ent      = @{ File = 'windows-11-enterprise-eval.iso';      Build = '';        Sha256 = '' }
    }
}
