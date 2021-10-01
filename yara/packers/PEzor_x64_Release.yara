rule PEzor_x64_Release {
    meta:
        author = "Still"
        class = "GA"
        component_name = "PEzor"
        create_date = "2021-08-05"
        description = "attempts to match the PEzor packer (release; x64)"
        last_modified = "2021-08-05"
        // compiled against a variety of packed hello world exe
        sample_hash = "N/A"
    strings:
	/*
	0x401588 488D442440                    lea rax, [rsp + 0x40]
	0x40158d 4889442420                    mov qword ptr [rsp + 0x20], rax
	0x401592 48C7C1FFFFFFFF                mov rcx, -1
	0x401599 4889DA                        mov rdx, rbx
	0x40159c 4989F8                        mov r8, rdi
	0x40159f 4989E9                        mov r9, rbp
	0x4015a2 FF15841C0100                  call qword ptr [rip + 0x11c84]
	 */
		$inst_required_WriteProcessMemory_std = {
			48 8D 44 24 ??
			48 89 44 24 ??
			48 C7 C1 FF FF FF FF
			48 89 ??
			49 89 ??
			[3-6]
			FF 15 ?? ?? ?? ??
		}
	/*
	0x6a0c1535 488D4C2410                    lea rcx, [rsp + 0x10]
	0x6a0c153a 49C7C2FFFFFFFF                mov r10, -1
	0x6a0c1541 4989F0                        mov r8, rsi
	0x6a0c1544 4883EC30                      sub rsp, 0x30
	0x6a0c1548 48894C2428                    mov qword ptr [rsp + 0x28], rcx
	0x6a0c154d 0F05                          syscall 
	 */
		$inst_required_WriteProcessMemory_syscall = {
			48 8D 4C 24 ??
			49 C7 C2 FF FF FF FF
			49 89 F0
			48 83 EC 30
			48 89 4C 24 ??
			0F 05
		}
	/*
	0x40155f 48C7C1FFFFFFFF                mov rcx, -1
	0x401566 31D2                          xor edx, edx
	0x401568 4989E8                        mov r8, rbp
	0x40156b 41B900300000                  mov r9d, 0x3000
	0x401571 FF15951C0100                  call qword ptr [rip + 0x11c95]
	 */
		$inst_required_VirtualAllocEx_std = {
			48 C7 C1 FF FF FF FF
			31 D2
			49 89 ??
			41 B9 00 30 00 00
			FF 15 ?? ?? ?? ??
		}
	/*
	0x6a0c14ee 49C7C2FFFFFFFF                mov r10, -1
	0x6a0c14f5 4531C0                        xor r8d, r8d
	0x6a0c14f8 4883EC40                      sub rsp, 0x40
	0x6a0c14fc 48C744242800300000            mov qword ptr [rsp + 0x28], 0x3000
	0x6a0c1505 48C744243040000000            mov qword ptr [rsp + 0x30], 0x40
	0x6a0c150e 0F05                          syscall 
	 */
		$inst_required_VirtualAllocEx_syscall = {
			49 C7 C2 FF FF FF FF
			45 31 C0
			48 83 EC 40
			48 C7 44 24 ?? 00 30 00 00
			48 C7 44 24 ?? 40 00 00 00
			0F 05
		}
	/*
	0x401656 488B052BDE0000                mov rax, qword ptr [rip + 0xde2b]
	0x40165d 8B10                          mov edx, dword ptr [rax]
	0x40165f 488B057ADE0000                mov rax, qword ptr [rip + 0xde7a]
	0x401666 8B00                          mov eax, dword ptr [rax]
	0x401668 89442420                      mov dword ptr [rsp + 0x20], eax
	0x40166c 488B0D0DDE0000                mov rcx, qword ptr [rip + 0xde0d]
	0x401673 4C8D442430                    lea r8, [rsp + 0x30]
	0x401678 41B901000000                  mov r9d, 1
	0x40167e E8ADFEFFFF                    call 0x401530
	 */
		$inst_required_inject_shellcode_call_std = {
			48 8B 05 ?? ?? ?? ??
			8B 10
			48 8B 05 ?? ?? ?? ??
			8B 00
			89 44 24 ??
			48 8B 0D ?? ?? ?? ??
			4C 8D 44 24 ??
		}
	/*
	0x6a0c1642 48C7442430FFFFFFFF            mov qword ptr [rsp + 0x30], -1
	0x6a0c164b 488B05861F0200                mov rax, qword ptr [rip + 0x21f86]
	0x6a0c1652 8B10                          mov edx, dword ptr [rax]
	0x6a0c1654 488B05951F0200                mov rax, qword ptr [rip + 0x21f95]
	0x6a0c165b 8B00                          mov eax, dword ptr [rax]
	0x6a0c165d 89442420                      mov dword ptr [rsp + 0x20], eax
	0x6a0c1661 488B0D681F0200                mov rcx, qword ptr [rip + 0x21f68]
	0x6a0c1668 4C8D442430                    lea r8, [rsp + 0x30]
	0x6a0c166d 4531C9                        xor r9d, r9d
	0x6a0c1670 E81BFEFFFF                    call 0x6a0c1490
	 */
		$inst_required_inject_shellcode_call_syscall = {
			48 C7 44 24 ?? FF FF FF FF
			48 8B 05 ?? ?? ?? ??
			8B 10
			48 8B 05 ?? ?? ?? ??
			8B 00
			89 44 24 ??
			48 8B 0D ?? ?? ?? ??
			4C 8D 44 24 ??
			45 31 C9
			E8 ?? ?? ?? ??
		}
	/*
	0x40b650 DBE3                          fninit 
	0x40b652 C3                            ret 
	 */
		$inst_optional_fninit = {
			DB E3
			C3
		}
	/*
	0x401500 4883EC28                      sub rsp, 0x28
	0x401504 E85FBA0000                    call 0x40cf68
	0x401509 4885C0                        test rax, rax
	0x40150c 0F94C0                        sete al
	0x40150f 0FB6C0                        movzx eax, al
	0x401512 F7D8                          neg eax
	0x401514 4883C428                      add rsp, 0x28
	0x401518 C3                            ret 
	 */
		$inst_optional_onexit = {
			48 83 EC 28
			E8 ?? ?? ?? ??
			48 85 C0
			0F 94 C0
			0F B6 C0
			F7 D8
			48 83 C4 28
			C3
		}
	/*
	0x40cfe0 4889C8                        mov rax, rcx
	0x40cfe3 488705C6510000                xchg qword ptr [rip + 0x51c6], rax
	0x40cfea C3                            ret 
	 */
		$inst_optional_InterlockedExchange64 = {
			48 89 C8
			48 87 05 ?? ?? ?? ??
			C3
		}
	/*
	0x6608148c FF15C22C0100                  call qword ptr [rip + 0x12cc2]
	0x66081492 3D57040000                    cmp eax, 0x457
	0x66081497 7562                          jne 0x660814fb
	 */
		$inst_optional_anti_debug_GetLastError = {
			FF 15 ?? ?? ?? ??
			3D 57 04 00 00
			75 ??
		}
	/*
	0x63a819b0 65488B042560000000            mov rax, qword ptr gs:[0x60]
	0x63a819b9 488B4018                      mov rax, qword ptr [rax + 0x18]
	0x63a819bd 488B4020                      mov rax, qword ptr [rax + 0x20]
	 */
		$inst_optional_get_ldr = {
			65 48 8B 04 25 ?? ?? ?? ??
			48 8B 40 ??
			48 8B 40 ??
		}
	/*
	0x68781e78 0FB74C5A08                    movzx ecx, word ptr [rdx + rbx*2 + 8]
	0x68781e7d 89CE                          mov esi, ecx
	0x68781e7f C1EE0C                        shr esi, 0xc
	0x68781e82 83C6FF                        add esi, -1
	0x68781e85 6683FE09                      cmp si, 9
	0x68781e89 77E5                          ja 0x68781e70
	0x68781e8b 0FB7F6                        movzx esi, si
	0x68781e8e 486334B7                      movsxd rsi, dword ptr [rdi + rsi*4]
	0x68781e92 4801FE                        add rsi, rdi
	0x68781e95 FFE6                          jmp rsi
	 */
		$inst_optional_unhook_reload_modules={
			0F B7 [3]
			89 ??
			C1 ?? 0C
			83 ?? FF
			66 83 ?? 09
			77 ??
			0F B7 ??
			48 63 [2]
			48 01 ??
			FF ??
		}
    condition:
        any of ($inst_required_WriteProcessMemory_*) and
        any of ($inst_required_VirtualAllocEx_*) and
        any of ($inst_required_inject_shellcode_call_*) and
        2 of ($inst_optional_*)
}
