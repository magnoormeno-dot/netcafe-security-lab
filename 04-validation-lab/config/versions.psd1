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
        Version = '15.20'                # Sysinternals Sysmon (Sysmon64.exe from Sysmon.zip, downloaded 2026-06-04)
        Sha256  = 'D8115212A7747010593DE813404B02D05B915E4B1D0231502B856B9ACE9274E8'  # Sysmon64.exe
        Source  = 'https://learn.microsoft.com/sysinternals/downloads/sysmon'
    }

    SysmonConfig = @{
        Repo      = 'https://github.com/SwiftOnSecurity/sysmon-config'
        # Pin to a REVIEWED commit instead of master so the baseline can't drift under you.
        PinCommit = '1836897f12fbd6a0a473665ef6abc34a6b497e31'  # last change to sysmonconfig-export.xml (2021-10-17)
        File      = 'sysmonconfig-export.xml'
        Sha256    = '055FEBC600E6D7448CDF3812307275912927A62B1F94D0D933B64B294BC87162'  # at the pinned commit
    }

    Wazuh = @{
        Version = '4.9.2'                # wazuh-agent-4.9.2-1.msi (latest in the 4.9 line, downloaded 2026-06-04)
        Sha256  = '88B40D63185D308C898DC237B0D5BA0EE1CA2AB41E6B38DB28D1D6B3B20A616D'  # agent MSI
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
        Ubuntu        = @{ File = 'ubuntu-24.04-live-server-amd64.iso'; Build = '24.04.x'; Sha256 = 'E907D92EEEC9DF64163A7E454CBC8D7755E8DDC7ED42F99DBC80C40F1A138433' }
        WinServer2022 = @{ File = 'windows-server-2022-eval.iso';        Build = '20348';   Sha256 = '3E4FA6D8507B554856FC9CA6079CC402DF11A8B79344871669F0251535255325' }
        Win11Ent      = @{ File = 'windows-11-enterprise-eval.iso';      Build = '26200';   Sha256 = 'A61ADEAB895EF5A4DB436E0A7011C92A2FF17BB0357F58B13BBC4062E535E7B9' }
    }
}
