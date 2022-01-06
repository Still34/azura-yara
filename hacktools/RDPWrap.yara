rule HackTool_RDPWrap {
  meta:
    author = "Still"
    component_name = "RDPWrap"
    create_date = "2021-12-16"
    description = "attempts to match the strings found in RDPWrap"
    last_modified = "2021-12-16"
    sample_hash = "3f04f0e08908e52d67c94a067978c959"
  strings:
    $str_1 = "SvcGlobals: termsrv.dll+0x%p"
    $str_2 = "SLGetWindowsInformationDWORD"
    $str_3 = "Initializing RDP Wrapper"
    $str_4 = "SLInit [0x%p] lMaxUserSessions"
    $str_5 = "SLInit [0x%p] bFUSEnabled"
    $str_6 = "Freezing threads..."
    $str_7 = "rdpwrap.dll"
  condition:
    3 of ($str_*)
}
