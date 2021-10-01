rule PEzor_x86_Release {
    meta:
        author = "Still"
        class = "GA"
        component_name = "PEzor"
        create_date = "2021-08-05"
        description = "attempts to match the PEzor packer (release; x86)"
        last_modified = "2021-08-05"
        // compiled against a variety of packed hello world exe
        sample_hash = "N/A"
    strings:
	/*
	0x401537 51                            push ecx
	0x401538 57                            push edi
	0x401539 50                            push eax
	0x40153a 56                            push esi
	0x40153b 6AFF                          push -1
	0x40153d FF151C014100                  call dword ptr [0x41011c]
	 */
		$inst_required_WriteProcessMemory = {
			51
			57
			50
			56
			6A FF
			FF 15 ?? ?? ?? ??
		}
	/*
	0x401512 6A40                          push 0x40
	0x401514 6800300000                    push 0x3000
	0x401519 57                            push edi
	0x40151a 6A00                          push 0
	0x40151c 6AFF                          push -1
	0x40151e FF150C014100                  call dword ptr [0x41010c]
	 */
		$inst_required_VirtualAllocEx = {
			6A ??
			68 00 30 00 00
			57
			6A 00
			6A FF
			FF 15 ?? ?? ?? ??
		}
	/*
	0x61b014fd A144E1B061                    mov eax, dword ptr [0x61b0e144]
	0x61b01502 8B0D4CE1B061                  mov ecx, dword ptr [0x61b0e14c]
	0x61b01508 89E2                          mov edx, esp
	0x61b0150a 8B3540E1B061                  mov esi, dword ptr [0x61b0e140]
	0x61b01510 FF31                          push dword ptr [ecx]
	0x61b01512 6A00                          push 0
	0x61b01514 52                            push edx
	0x61b01515 FF30                          push dword ptr [eax]
	0x61b01517 56                            push esi
	0x61b01518 E8F3FEFFFF                    call 0x61b01410
	 */
		$inst_required_shellcode_injection_call = {
			A1 ?? ?? ?? ??
			8B 0D ?? ?? ?? ??
			[2-4]
			8B 35 ?? ?? ?? ??
			FF 31
			6A ??
			52
			FF 30
			56
			E8 ?? ?? ?? ??
		}
	/*
	0x40b650 DBE3                          fninit 
	0x40b652 C3                            ret 
	 */
		$inst_required_fninit = {
			DB E3
			C3
		}
	/*
	0x40b43f 85DB                          test ebx, ebx
	0x40b441 7411                          je 0x40b454
	0x40b443 8D742600                      lea esi, [esi]
	0x40b447 90                            nop 
	0x40b448 FF149D20C44000                call dword ptr [ebx*4 + 0x40c420]
	0x40b44f 83EB01                        sub ebx, 1
	0x40b452 75F4                          jne 0x40b448
	 */
		$inst_optional_loop = {
			85 DB
			74 ??
			8D 74 26 ??
			90
			FF 14 9D ?? ?? ?? ??
			83 EB 01
			75 ??
		}
	/*
	0x4014d0 83EC1C                        sub esp, 0x1c
	0x4014d3 8B442420                      mov eax, dword ptr [esp + 0x20]
	0x4014d7 890424                        mov dword ptr [esp], eax
	0x4014da E8BDAE0000                    call 0x40c39c
	0x4014df 85C0                          test eax, eax
	0x4014e1 0F94C0                        sete al
	0x4014e4 83C41C                        add esp, 0x1c
	0x4014e7 0FB6C0                        movzx eax, al
	0x4014ea F7D8                          neg eax
	0x4014ec C3                            ret 
	 */
		$inst_optional_onexit = {
			83 EC 1C
			8B 44 24 ??
			89 04 24
			E8 ?? ?? ?? ??
			85 C0
			0F 94 C0
			83 C4 1C
			0F B6 C0
			F7 D8
			C3
		}
	/*
	0x40c410 8B442404                      mov eax, dword ptr [esp + 4]
	0x40c414 8705A8F04000                  xchg dword ptr [0x40f0a8], eax
	0x40c41a C3                            ret 
	 */
		$inst_optional_InterlockedExchange = {
			8B 44 24 ??
			87 05 ?? ?? ?? ??
			C3
		}
	/*
	0x40af0d 64A118000000                  mov eax, dword ptr fs:[0x18]
	0x40af13 33C9                          xor ecx, ecx
	0x40af15 56                            push esi
	0x40af16 8B4030                        mov eax, dword ptr [eax + 0x30]
	0x40af19 8B400C                        mov eax, dword ptr [eax + 0xc]
	0x40af1c 8B700C                        mov esi, dword ptr [eax + 0xc]
	0x40af1f EB20                          jmp 0x40af41
	 */
		$inst_optional_get_ldr = {
			64 A1 ?? ?? ?? ??
			33 C9
			56
			8B 40 ??
			8B 40 ??
			8B 70 ??
		}
	
    condition:
        3 of ($inst_required_*) and any of ($inst_optional_*)
}
