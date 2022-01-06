rule HackTool_PS1ToExe {
    meta:
        author = "Still34"
        license = "GPL-3.0"
        component_name = "PS1ToExe"
        create_date = "2021-11-23"
        description = "attempts to match Faith Kodak's PS1 to Exe PowerShell script loader"
        last_modified = "2021-01-05"
        // https://f2ko.de/programme/ps1-to-exe/
        sample_hash = "b75a4029a1166ad095adc63282bf6d08"
        triage_score = 6
        triage_tags = "faith_kodak"
        triage_description = "Uses Faith Kodak's PS1 to Exe PowerShell script loader."
    strings:
        $pe_import_section = ".code"
	/*
	0x14000e0a4 448B4110                      mov r8d, dword ptr [rcx + 0x10]
	0x14000e0a8 488B5108                      mov rdx, qword ptr [rcx + 8]
	0x14000e0ac 4C8D4C2440                    lea r9, [rsp + 0x40]
	0x14000e0b1 442B4114                      sub r8d, dword ptr [rcx + 0x14]
	0x14000e0b5 488B09                        mov rcx, qword ptr [rcx]
	0x14000e0b8 4889442420                    mov qword ptr [rsp + 0x20], rax
	0x14000e0bd FF15D5160100                  call qword ptr [rip + 0x116d5]
	 */
		$chunk_1 = {
			44 8B 41 ??
			48 8B 51 ??
			4C 8D 4C 24 ??
			44 2B 41 ??
			48 8B 09
			48 89 44 24 ??
			FF 15 ?? ?? ?? ??
		}
	/*
	0x40ab06 8D442408                      lea eax, [esp + 8]
	0x40ab0a 50                            push eax
	0x40ab0b 8B4608                        mov eax, dword ptr [esi + 8]
	0x40ab0e 2B460C                        sub eax, dword ptr [esi + 0xc]
	0x40ab11 50                            push eax
	0x40ab12 FF7604                        push dword ptr [esi + 4]
	0x40ab15 FF36                          push dword ptr [esi]
	0x40ab17 FF15E4744100                  call dword ptr [0x4174e4]
	 */
		$chunk_2 = {
			8D 44 24 ??
			50
			8B 46 ??
			2B 46 ??
			50
			FF 76 ??
			FF 36
			FF 15 ?? ?? ?? ??
		}
    $secret_constant = {FF FF FF FF FF FF FF FF 7F 3B D5 06 ?? ?? ?? ??}
    condition:
      $pe_import_section and
      $secret_constant and
      any of ($chunk_*)
}