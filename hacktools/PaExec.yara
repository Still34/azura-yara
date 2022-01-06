rule Suspicious_PaExec {
    meta:
        author = "Still34"
        license = "GPL-3.0"
        component_name = "PaExec"
        create_date = "2021-12-07"
        description = "attempts to match the open-source reimplementation of PsExec, PaExec"
        last_modified = "2021-12-07"
        sample_hash = "32b5741594bb411ab107f21373a0e0cba4fa1e4538b6459b5d4bca7cf8d7c76e"
    strings:
        $str_1 = "PAExec %s - Execute Programs Remotely" wide
        $str_2 = "PAExec error waiting for app to exit" wide
        $str_3 = "Starting PAExec service on %s..." wide
        $str_4 = "WTSGetActiveConsoleSessionId not supported on this OS" wide
        $str_5 = "\\\\.\\pipe\\PAExecErr%s%u" wide
        $str_6 = "\\\\.\\pipe\\PAExecIn%s%u" wide
        $str_7 = "\\\\.\\pipe\\PAExecOut%s%u" wide
        $str_8 = "Using SessionID %u (interactive session)" wide 
        $str_9 = "Failed to connect to Service Control Manager on %s." wide 
	/*
	0x4026e4 50                            push eax
	0x4026e5 8B06                          mov eax, dword ptr [esi]
	0x4026e7 660F1385B4FEFFFF              movlpd qword ptr [ebp - 0x14c], xmm0
	0x4026ef FFB094000000                  push dword ptr [eax + 0x94]
	0x4026f5 FF1500414200                  call dword ptr [0x424100]
	0x4026fb 85C0                          test eax, eax
	0x4026fd 7409                          je 0x402708
	0x4026ff 83BDDCFEFFFF00                cmp dword ptr [ebp - 0x124], 0
	0x402706 7511                          jne 0x402719
	 */
		$inst_ListenRemoteOutPipeThread = {
			50
			8B 06
			66 0F 13 85 ?? ?? ?? ??
			FF B0 ?? ?? ?? ??
			FF 15 ?? ?? ?? ??
			85 C0
			74 ??
			83 BD ?? ?? ?? ?? 00
			75 ??
		}
	/*
	0x402afa 50                            push eax
	0x402afb 8D85D4FEFFFF                  lea eax, [ebp - 0x12c]
	0x402b01 0F57C0                        xorps xmm0, xmm0
	0x402b04 50                            push eax
	0x402b05 68FF000000                    push 0xff
	0x402b0a 8D85F0FEFFFF                  lea eax, [ebp - 0x110]
	0x402b10 660F138590FEFFFF              movlpd qword ptr [ebp - 0x170], xmm0
	 */
		$inst_ListenRemoteStdInputPipeThread = {
			50
			8D 85 ?? ?? ?? ??
			0F 57 C0
			50
			68 FF 00 00 00
			8D 85 ?? ?? ?? ??
			66 0F 13 85 ?? ?? ?? ??
		}
    condition:
        4 of ($str_*) or all of ($inst_*)
}
