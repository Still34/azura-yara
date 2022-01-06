rule HackTool_SharpSploit {
    meta:
        author = "Still"
        component_name = "SharpSploit"
        create_date = "2021-11-08"
        description = "attempts to match the strings found in the SharpSploit toolkit"
        last_modified = "2021-11-08"
        //  https://github.com/cobbr/SharpSploit
        sample_hash = "70c7b16651c46171932532c5fac9a120"
    strings:
        $str_member_1 = "PrivExchangePushNotification" ascii
        $str_member_2 = "CreateReversePortForward" ascii
        $str_member_3 = "InstallWMIPersistence" ascii
        $str_member_4 = "PowerShellRemoting" ascii
        $str_member_5 = "System.Management.Automation.Tracing.PSEtwLogProvider" ascii
        $str_member_6 = "VirtualAllocAllocationTechnique" ascii
        $str_member_7 = "PatchAmsiScanBuffer" ascii
        $str_member_8 = "StartClipboardMonitor" ascii
        $str_member_9 = "Finished Keylogger at {0:HH:mm:ss.fff}" wide
        $str_member_10 = "powershell_reflective_mimikatz" ascii wide
    condition:
        3 of them
}
