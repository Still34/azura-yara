rule Amber_Standard_x64 {
    meta:
        author = "Still34"
        license = "GPL-3.0"
        component_name = "Amber"
        create_date = "2021-08-06"
        description = "attempts to match an x64 executable that has been packed with the -b parameter with Amber"
        last_modified = "2021-08-06"
        sample_hash = "N/A"
    strings:
	/*
	0x401662 488B45F8                      mov rax, qword ptr [rbp - 8]
	0x401666 8B4010                        mov eax, dword ptr [rax + 0x10]
	0x401669 89C0                          mov eax, eax
	0x40166b 41B940000000                  mov r9d, 0x40
	0x401671 41B800100000                  mov r8d, 0x1000
	0x401677 4889C2                        mov rdx, rax
	0x40167a B900000000                    mov ecx, 0
	0x40167f 488B05366C0000                mov rax, qword ptr [rip + 0x6c36]
	0x401686 FFD0                          call rax
	 */
		$inst_VirtualAlloc = {
			48 8B 45 ??
			8B 40 ??
			89 C0
			41 B9 40 00 00 00
			41 B8 00 10 00 00
			48 89 C2
			B9 00 00 00 00
			48 8B 05 ?? ?? ?? ??
			FF D0
		}
	/*
	0x40168c 488B45F8                      mov rax, qword ptr [rbp - 8]
	0x401690 8B4010                        mov eax, dword ptr [rax + 0x10]
	0x401693 89C1                          mov ecx, eax
	0x401695 488B45F8                      mov rax, qword ptr [rbp - 8]
	0x401699 8B400C                        mov eax, dword ptr [rax + 0xc]
	0x40169c 89C2                          mov edx, eax
	0x40169e 488B45C8                      mov rax, qword ptr [rbp - 0x38]
	0x4016a2 488B4030                      mov rax, qword ptr [rax + 0x30]
	0x4016a6 4801D0                        add rax, rdx
	0x4016a9 4889C2                        mov rdx, rax
	0x4016ac 488B45B8                      mov rax, qword ptr [rbp - 0x48]
	0x4016b0 4989C8                        mov r8, rcx
	0x4016b3 4889C1                        mov rcx, rax
	0x4016b6 E8A5150000                    call 0x402c60
	 */
		$inst_memcpy = {
			48 8B 45 ??
			8B 40 ??
			89 C1
			48 8B 45 ??
			8B 40 ??
			89 C2
			48 8B 45 ??
			48 8B 40 ??
			48 01 D0
			48 89 C2
			48 8B 45 ??
			49 89 C8
			48 89 C1
			E8 ?? ?? ?? ??
		}
	/*
	0x401614 488B45D8                      mov rax, qword ptr [rbp - 0x28]
	0x401618 41B800000000                  mov r8d, 0
	0x40161e BA00000000                    mov edx, 0
	0x401623 4889C1                        mov rcx, rax
	0x401626 488B05D76B0000                mov rax, qword ptr [rip + 0x6bd7]
	0x40162d FFD0                          call rax
	 */
		$inst_FlushInstructionCache = {
			48 8B 45 ??
			41 B8 00 00 00 00
			BA 00 00 00 00
			48 89 C1
			48 8B 05 ?? ?? ?? ??
			FF D0
		}
	/*
	0x401524 E877170000                    call 0x402ca0
	0x401529 4885C0                        test rax, rax
	0x40152c 0F94C0                        sete al
	0x40152f 0FB6C0                        movzx eax, al
	0x401532 F7D8                          neg eax
	0x401534 4883C428                      add rsp, 0x28
	 */
		$inst_onexit = {
			E8 ?? ?? ?? ??
			48 85 C0
			0F 94 C0
			0F B6 C0
			F7 D8
			48 83 C4 28
		}
	
    condition:
        all of them
}
