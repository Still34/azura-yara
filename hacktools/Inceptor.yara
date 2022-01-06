rule HackTool_Inceptor {
    meta:
        author = "Still34"
        license = "GPL-3.0"
        component_name = "Inceptor"
        create_date = "2021-10-26"
        description = "attempts to match the instructions and strings used in the Inceptor red teaming toolkit"
        last_modified = "2021-10-26"
        // https://github.com/klezVirus/inceptor
        sample_hash = "f90b8a0b2cc0021290fa96b21d06682f"
    strings:
        $str_debug_1 = "[*] Allocating %d bytes of memory"
        $str_debug_2 = "[+] The shellcode finished with a return value"
        $str_debug_3 = "[-] Missing PID... Finding..."
        $str_debug_4 = "[-] Process not found"
        $str_debug_5 = "[*] Injecting into remote process using direct syscalls"
        $str_debug_6 = "[+] Injected into remote process"
	/*
	0x1400049c1 8B0DF5AE0200                  mov ecx, dword ptr [rip + 0x2aef5]
	0x1400049c7 8D59FF                        lea ebx, [rcx - 1]
	0x1400049ca 0FAFD9                        imul ebx, ecx
	0x1400049cd 4189D8                        mov r8d, ebx
	0x1400049d0 41F7D0                        not r8d
	 */
		$inst_1 = {
			8B 0D ?? ?? ?? ??
			8D 59 ??
			0F AF D9
			41 89 D8
			41 F7 D0
		}
	
    condition:
        2 of ($str_debug_*) or any of ($inst_*)
}
