rule PEzor_COFF {
    meta:
        author = "Still34"
        license = "GPL-3.0"
        component_name = "PEzor"
        create_date = "2021-08-05"
        description = "attempts to match the PEzor packer (bof format)"
        last_modified = "2021-08-05"
        // compiled against a variety of packed hello world exe
        sample_hash = "N/A"
    strings:
        $str_1 = "[PEzor] starting BOF..."
        $str_2 = "inject_shellcode_self"
        $str_3 = "WAIT_ABANDONED"
        $str_4 = "WAIT_FAILED"
	/*
	0x792 6A40                          push 0x40
	0x794 6800300000                    push 0x3000
	0x799 57                            push edi
	0x79a 6A00                          push 0
	0x79c 6AFF                          push -1
	0x79e FF157CAA0000                  call dword ptr [0xaa7c]
	 */
		$inst_VirtualAllocEx = {
			6A 40
			68 00 30 00 00
			57
			6A 00
			6A FF
			FF 15 ?? ?? ?? ??
		}
	/*
	0x7b5 89E1                          mov ecx, esp
	0x7b7 51                            push ecx
	0x7b8 57                            push edi
	0x7b9 50                            push eax
	0x7ba 56                            push esi
	0x7bb 6AFF                          push -1
	0x7bd FF1580AA0000                  call dword ptr [0xaa80]
	 */
		$inst_WriteProcessMemory = {
			89 E1
			51
			57
			50
			56
			6A FF
			FF 15 ?? ?? ?? ??
		}
	/*
	0x7c9 8B5C241C                      mov ebx, dword ptr [esp + 0x1c]
	0x7cd 6A00                          push 0
	0x7cf 6A00                          push 0
	0x7d1 56                            push esi
	0x7d2 56                            push esi
	0x7d3 6A00                          push 0
	0x7d5 6A00                          push 0
	0x7d7 6AFF                          push -1
	0x7d9 FF1584AA0000                  call dword ptr [0xaa84]
	 */
		$inst_CreateRemoteThread = {
			8B 5C 24 ??
			6A 00
			6A 00
			56
			56
			6A 00
			6A 00
			6A FF
			FF 15 ?? ?? ?? ??
		}
	/*
	0x508 6A00                          push 0
	0x50a 8D442428                      lea eax, [esp + 0x28]
	0x50e 50                            push eax
	0x50f 6A00                          push 0
	0x511 6A00                          push 0
	0x513 6A00                          push 0
	0x515 FF742430                      push dword ptr [esp + 0x30]
	0x519 FF1590AA0000                  call dword ptr [0xaa90]
	 */
		$inst_PeekNamedPipe = {
			6A 00
			8D 44 24 ??
			50
			6A 00
			6A 00
			6A 00
			FF 74 24 ??
			FF 15 ?? ?? ?? ??
		}
    condition:
        all of ($str_*) or
        2 of ($str_*) and 3 of ($inst_*)
}
