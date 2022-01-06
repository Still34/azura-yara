rule Suspicious_ProcDump {
    meta:
        author = "Still"
        component_name = "ProcDump"
        description = "attempt to match Sysinternals ProcDump"
        last_modified = "2021-04-19"
        sample_hash = "f13dab7d9ce88ddc0c80c2b9c5f422b5, d3763ffbfaf30bcfd866b8ed0324e7a3"
    strings:
        $str_general_1 = /[Ss]ysinternals/
        $str_general_2 = /[Pp]roc[Dd]ump/
        $str_1 = "f:\\Agent\\_work\\17\\s\\x64\\Release\\ProcDump64.pdb" wide
        $str_2 = "SOFTWARE\\Microsoft\\Windows Kits\\Installed Roots" wide
        $str_3 = "*** Hung window detected" wide
        $str_4 = "ProcDump Dump Engine" wide
        $str_5 = "Already at dump count" wide
        $str_6 = /via Process (Reflection|Snapshot)/ wide
        $str_7 = "ProcmonDebugLogger" wide
    condition:
        7 of them
}
