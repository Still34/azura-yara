rule SharpBeacon {
    meta:
        author = "Still34"
        license = "GPL-3.0"
        component_name = "SharpBeacon"
        create_date = "2021-11-10"
        description = "attempts to match the open-source .NET reimplementation of CobaltStrike Beacon"
        last_modified = "2021-11-10"
        // https://github.com/mai1zhi2/SharpBeacon
        sample_hash = "fa6d54df61740fee2831b03dafac11d5"
    strings:
        $root_module_1 = "mscoree" ascii
        $root_module_2 = "mscorlib" ascii
        $log_1 = ", Dll was not found." wide 
        $log_2 = "There is an IOException" wide 
        $log_3 = {0d 4e fd 80 3a 4e 7a 7a 47 00 75 00 69 00 64 00} //不能为空Guid
        $log_4 = {90 6e 87 65 f6 4e 0d 4e 58 5b 28 57} //源文件不存在
        $log_5 = {50 00 69 00 64 00 09 00 50 00 70 00 69 00 64 00 09 00 4e 00 61 00 6d 00 65 00 09 00 50 00 61 00 74 00 68 00 09 00 53 00 65 00 73 00 73 00 69 00 6f 00 6e 00 49 00 44 00 09 00 4f 00 77 00 6e 00 65 00 72 00 09 00 41 00 72 00 63 00 68 00 69 00 74 00 65 00 63 00 74 00 75 00 72 00 65 00} // Pid\tPpid\tName\tPath\tSessionID\tOwner\tArchitecture
        $member_1 = "GetBeaconID"
        $member_2 = "TokenIsElevated"
        $member_3 = "EnableCurrentProcessTokenPrivilege"
        $member_4 = "BeaconResultProperty"
        $member_5 = "SharpSploitResultList"
        $member_6 = "ReversePortFwdResult"
        $member_7 = "PatchETWEventWrite"
        $member_8 = "CreateRemoteThreadInjectShellCode"
        $inst_inject_shellcode = {
            12 ?? 02 28 [4] 7d [4] 12 00 20 [4] 12 01 12 02 28
        }
        $inst_CreateProcessWithLogon={
            08
            6F [4]
            6F [4]
            7D [4]
            12 04
            08
            6F [4]
            6F [4]
            7D [4]
            12 04
            20 [4]
            7D [4]
            11 04
            0D
        }
    condition:
        any of ($root_module_*) and
        (
            3 of ($log_*) or
            4 of ($member_*) or
            all of ($inst_*)
        )
}
rule SharpStager {
    meta:
        author = "Still34"
        license = "GPL-3.0"
        component_name = "SharpBeacon"
        create_date = "2021-11-10"
        description = "attempts to match the open-source .NET reimplementation of CobaltStrike Stager"
        last_modified = "2021-11-10"
        // https://github.com/mai1zhi2/SharpBeacon
        sample_hash = "05ca8a073d4dc4c97cd66376ac7a5eed"
    strings:
        $root_module_1 = "mscoree" ascii
        $root_module_2 = "mscorlib" ascii
        $str_debug_1 = "Could not retrieve amsi.dll pointer!"
        $str_debug_2 = "Could not retrieve DllCanUnloadNow function pointer!"
        $str_header_1 = "zh - CN,zh; q = 0.8,zh - TW; q = 0.7,zh - HK; q = 0.5,en - US; q = 0.3,en; q = 0.2" wide
    condition:
        any of ($root_module_*) and 2 of ($str_*)
}