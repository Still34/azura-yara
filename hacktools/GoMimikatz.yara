rule HackTool_GoMimikatz {
  	meta:
		author = "Still"
		component_name = "Mimikatz"
		create_date = "2021-12-17"
		// https://github.com/vyrus001/go-mimikatz.
		description = "attempts to match Mimikatz wrapped in go"
		last_modified = "2021-12-17"
		sample_hash = "606579f189885467dd306d4c77966b6892add5bc8e4acec9b530cf444df9d86e"
	strings:
		$str_repo = "github.com/vyrus001/go-mimikatz"
		$str_stub = "/stub/stub.go"
	/*
	0x464b6a 460FB61C10                    movzx r11d, byte ptr [rax + r10]
	0x464b6f 4531CB                        xor r11d, r9d
	0x464b72 45881C02                      mov byte ptr [r10 + rax], r11b
	0x464b76 48FFC0                        inc rax
	 */
		$inst_xor_padding = {
			46 0F B6 1C 10
			45 31 CB
			45 88 1C 02
			48 FF C0
		}
	/*
	0x464bab 4889442428                    mov qword ptr [rsp + 0x28], rax
	0x464bb0 31DB                          xor ebx, ebx
	0x464bb2 4889D9                        mov rcx, rbx
	0x464bb5 4889CF                        mov rdi, rcx
	0x464bb8 4889CE                        mov rsi, rcx
	0x464bbb 0F1F440000                    nop dword ptr [rax + rax]
	0x464bc0 E8BB4CFFFF                    call 0x459880
	 */
		$inst_syscall = {
			48 89 44 24 ??
			31 DB
			48 89 D9
			48 89 CF
			48 89 CE
			0F 1F 44 00 ??
			E8 ?? ?? ?? ??
		}
  condition:
    all of ($str_*) or
    any of ($inst_*)
}
