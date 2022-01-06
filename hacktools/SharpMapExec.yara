rule HackTool_SharMapExec {
    meta:
        author = "Still34"
        license = "GPL-3.0"
        component_name = "SharpMapExec"
        create_date = "2021-12-01"
        description = "attempts to match instructions/strings found in SharpMapExec"
        last_modified = "2021-12-01"
        sample_hash = "c299a18b879c074840aacc856be8b271"
    strings:
		/* 0x000248E9 284900002B    IL_0009: call      class [mscorlib]System.Collections.Generic.IEnumerable`1<!!0> [System.Core]System.Linq.Enumerable::Take<uint8>(class [mscorlib]System.Collections.Generic.IEnumerable`1<!!0>, int32) */
		/* 0x000248EE 281D00002B    IL_000E: call      !!0[] [System.Core]System.Linq.Enumerable::ToArray<uint8>(class [mscorlib]System.Collections.Generic.IEnumerable`1<!!0>) */
		/* 0x000248F3 2837090006    IL_0013: call      instance void SharpMapExec.HiveParser.LsaSecret::set_version(uint8[]) */
		/* 0x000248F8 02            IL_0018: ldarg.0 */
		/* 0x000248F9 03            IL_0019: ldarg.1 */
		/* 0x000248FA 1A            IL_001A: ldc.i4.4 */
		/* 0x000248FB 283B00002B    IL_001B: call      class [mscorlib]System.Collections.Generic.IEnumerable`1<!!0> [System.Core]System.Linq.Enumerable::Skip<uint8>(class [mscorlib]System.Collections.Generic.IEnumerable`1<!!0>, int32) */
		/* 0x00024900 1F10          IL_0020: ldc.i4.s  16 */
		/* 0x00024902 284900002B    IL_0022: call      class [mscorlib]System.Collections.Generic.IEnumerable`1<!!0> [System.Core]System.Linq.Enumerable::Take<uint8>(class [mscorlib]System.Collections.Generic.IEnumerable`1<!!0>, int32) */
		/* 0x00024907 281D00002B    IL_0027: call      !!0[] [System.Core]System.Linq.Enumerable::ToArray<uint8>(class [mscorlib]System.Collections.Generic.IEnumerable`1<!!0>) */
		/* 0x0002490C 2839090006    IL_002C: call      instance void SharpMapExec.HiveParser.LsaSecret::set_enc_key_id(uint8[]) */
		/* 0x00024911 02            IL_0031: ldarg.0 */
		/* 0x00024912 03            IL_0032: ldarg.1 */
		/* 0x00024913 1F14          IL_0033: ldc.i4.s  20 */
		/* 0x00024915 283B00002B    IL_0035: call      class [mscorlib]System.Collections.Generic.IEnumerable`1<!!0> [System.Core]System.Linq.Enumerable::Skip<uint8>(class [mscorlib]System.Collections.Generic.IEnumerable`1<!!0>, int32) */
		/* 0x0002491A 1A            IL_003A: ldc.i4.4 */
		/* 0x0002491B 284900002B    IL_003B: call      class [mscorlib]System.Collections.Generic.IEnumerable`1<!!0> [System.Core]System.Linq.Enumerable::Take<uint8>(class [mscorlib]System.Collections.Generic.IEnumerable`1<!!0>, int32) */
		/* 0x00024920 281D00002B    IL_0040: call      !!0[] [System.Core]System.Linq.Enumerable::ToArray<uint8>(class [mscorlib]System.Collections.Generic.IEnumerable`1<!!0>) */
		/* 0x00024925 283B090006    IL_0045: call      instance void SharpMapExec.HiveParser.LsaSecret::set_enc_algo(uint8[]) */
        $inst_LsaSecret_ctor = {
            28 [4]
            28 [4]
            28 [4]
            02
            03
            1A
            28 [4]
            1F 10
            28 [4]
            28 [4]
            28 [4]
            02
            03
            1F 14
            28 [4]
            1A
            28 [4]
            28 [4]
            28
        }
        /* 0x00025EE6 07            IL_0016: ldloc.1 */
        /* 0x00025EE7 6FA102000A    IL_0017: callvirt  instance class [mscorlib]System.IO.Stream [mscorlib]System.IO.BinaryReader::get_BaseStream() */
        /* 0x00025EEC 25            IL_001C: dup */
        /* 0x00025EED 6FA402000A    IL_001D: callvirt  instance int64 [mscorlib]System.IO.Stream::get_Position() */
        /* 0x00025EF2 2024100000    IL_0022: ldc.i4    4132 */
        /* 0x00025EF7 6A            IL_0027: conv.i8 */
        /* 0x00025EF8 07            IL_0028: ldloc.1 */
        /* 0x00025EF9 6FA102000A    IL_0029: callvirt  instance class [mscorlib]System.IO.Stream [mscorlib]System.IO.BinaryReader::get_BaseStream() */
        /* 0x00025EFE 6FA402000A    IL_002E: callvirt  instance int64 [mscorlib]System.IO.Stream::get_Position() */
        $inst_ImportHiveDump = {
            07
            6F [4]
            25
            6F [4]
            2024100000
            6A
            07
            6F [4]
            6F
        }
        /* 0x000299E3 02            IL_002B: ldarg.0 */
		/* 0x000299E4 06            IL_002C: ldloc.0 */
		/* 0x000299E5 1A            IL_002D: ldc.i4.4 */
		/* 0x000299E6 58            IL_002E: add */
		/* 0x000299E7 91            IL_002F: ldelem.u1 */
		/* 0x000299E8 1F53          IL_0030: ldc.i4.s  83 */
		/* 0x000299EA 334A          IL_0032: bne.un.s  IL_007E */
		/* 0x000299EC 02            IL_0034: ldarg.0 */
		/* 0x000299ED 06            IL_0035: ldloc.0 */
		/* 0x000299EE 1B            IL_0036: ldc.i4.5 */
		/* 0x000299EF 58            IL_0037: add */
		/* 0x000299F0 91            IL_0038: ldelem.u1 */
		/* 0x000299F1 1F53          IL_0039: ldc.i4.s  83 */
		/* 0x000299F3 3341          IL_003B: bne.un.s  IL_007E */
		/* 0x000299F5 02            IL_003D: ldarg.0 */
		/* 0x000299F6 06            IL_003E: ldloc.0 */
		/* 0x000299F7 1C            IL_003F: ldc.i4.6 */
		/* 0x000299F8 58            IL_0040: add */
		/* 0x000299F9 91            IL_0041: ldelem.u1 */
		/* 0x000299FA 1F50          IL_0042: ldc.i4.s  80 */
		/* 0x000299FC 3338          IL_0044: bne.un.s  IL_007E */
        $inst_Smb2Protocol_ExtractSSP ={
            02
            06
            1?
            58
            91
            1F (54|4C|4D|53|50)
            33 ??
            02
            06
            1?
            58
            91
            1F (54|4C|4D|53|50)
            33 ??
            02
            06
            1?
            58
            91
            1F (54|4C|4D|53|50)
            33 ??
            02
            06
            1?
            58
            91
            1F (54|4C|4D|53|50)
            33
        }
		/* 0x0002C6F7 26           IL_0043: pop  */
		/* 0x0002C6F8 7E55140004   IL_0044: ldsfld    class SharpMapExec.Helpers.AmsiFail/'<>c' SharpMapExec.Helpers.AmsiFail/'<>c'::'<>9'  */
		/* 0x0002C6FD FE06E30B0006 IL_0049: ldftn     instance string SharpMapExec.Helpers.AmsiFail/'<>c'::'<encodePayload>b__13_1'(class [System]System.Text.RegularExpressions.Match)  */
		/* 0x0002C703 73E603000A   IL_004F: newobj    instance void class [mscorlib]System.Func`2<class [System]System.Text.RegularExpressions.Match, string>::.ctor(object, native int)  */
		/* 0x0002C708 25           IL_0054: dup  */
		/* 0x0002C709 8058140004   IL_0055: stsfld    class [mscorlib]System.Func`2<class [System]System.Text.RegularExpressions.Match, string> SharpMapExec.Helpers.AmsiFail/'<>c'::'<>9__13_1'  */
		/* 0x0002C70E 286B00002B   IL_005A: call      class [mscorlib]System.Collections.Generic.IEnumerable`1<!!1> [System.Core]System.Linq.Enumerable::Select<class [System]System.Text.RegularExpressions.Match, string>(class [mscorlib]System.Collections.Generic.IEnumerable`1<!!0>, class [mscorlib]System.Func`2<!!0, !!1>)  */
		/* 0x0002C713 282700002B   IL_005F: call      class [mscorlib]System.Collections.Generic.List`1<!!0> [System.Core]System.Linq.Enumerable::ToList<string>(class [mscorlib]System.Collections.Generic.IEnumerable`1<!!0>)  */
		/* 0x0002C718 0A           IL_0064: stloc.0  */
        $inst_AmsiFail_EncodePayload = {
            26
            7E [4]
            FE [5]
            73 [4]
            25
            80 [4]
            28 [4]
            28 [4]
            0A
        }
        /* 0x0002ADD2 08          IL_0032: ldloc.2  */
		/* 0x0002ADD3 17          IL_0033: ldc.i4.1  */
		/* 0x0002ADD4 6FBA03000A  IL_0034: callvirt  instance void [System.Management.Automation]System.Management.Automation.Runspaces.WSManConnectionInfo::set_SkipCACheck(bool)  */
		/* 0x0002ADD9 08          IL_0039: ldloc.2  */
		/* 0x0002ADDA 20C0D40100  IL_003A: ldc.i4    120000  */
		/* 0x0002ADDF 6FCB03000A  IL_003F: callvirt  instance void [System.Management.Automation]System.Management.Automation.Runspaces.RunspaceConnectionInfo::set_IdleTimeout(int32)  */
        $inst_WsMan_InvokeCommand = {
            08
            17
            6F [4]
            08
            17
            6F [4]
            08
            20 C0 D4 01 00
        }
        /* 0x0002A9F4 73DE01000A   IL_00C8: newobj    instance void class [mscorlib]System.Collections.Generic.List`1<string>::.ctor() */
        /* 0x0002A9F9 1304         IL_00CD: stloc.s   readableShares */
        /* 0x0002A9FB 73DE01000A   IL_00CF: newobj    instance void class [mscorlib]System.Collections.Generic.List`1<string>::.ctor() */
        /* 0x0002AA00 1305         IL_00D4: stloc.s   unauthorizedShares */
        /* 0x0002AA02 09           IL_00D6: ldloc.3 */
        /* 0x0002AA03 0B           IL_00D7: stloc.1 */
        /* 0x0002AA04 16           IL_00D8: ldc.i4.0 */
        /* 0x0002AA05 0C           IL_00D9: stloc.2 */
        $inst_SMB_CheckLocalAdmin = {
            73 [4]
            13 0?
            73 [4]
            13 0?
            09
            0B
            16
            0C
        }
        $str_log_1 = "Could not find LogonSessionList signature" wide
        $str_log_2 = "Something goes wrong" wide
        $str_log_3 = "ntlm/rc4 OR aes128 OR aes256" wide
        $str_log_4 = "Using a domain DPAPI backup key to triage masterkeys for decryption key mappings" wide
        $str_log_5 = "Saving to users.json and policy.json to loot folder" wide
        $str_log_6 = "Requesting default etypes (RC4_HMAC, AES[128/256]_CTS_HMAC_SHA1) for the service ticket" wide
        $str_log_7 = "[0-9A-Fa-f]{32}[_][0-9A-Fa-f]{8}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{12}" wide
        $str_log_8 = "Possible script injection risk via the a dangerous method." wide
        $str_log_9 = "Untrusted input can cause arbitrary PowerShell expressions to be run." wide
        $str_log_10 = "Possible injection vulnerability found" wide
        $str_log_11 = "Possible property access injection via Foreach-Object." wide
        $str_posh_1 = "[System.Security.Principal.WindowsIdentity]::GetCurrent()" wide
        $str_posh_2 = "byte[] bin = Decompress(Convert.FromBase64String(\"{0}\"));" wide
        $str_posh_3 = "$Stream = New-Object IO.Compression.GZipStream([IO.MemoryStream][Convert]::FromBase64String($b64)" wide
        $str_posh_4 = "[ConsoleApp1.Program]::DelegWalk()" wide
        $str_posh_5 = "[Win32.advapi32]::OpenProcessToken($handle, 0x2, [ref]$hToken)" wide
        $str_posh_6 = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static')" wide
        $str_posh_7 = "If content escaping is truly needed, PowerShell has several valid quote characters, so  [System.Management.Automation.Language" wide
        $str_posh_8 = "so the  [System.Management.Automation.Language.CodeGeneration]::Escape* should be used instead" wide
    condition:
        3 of ($inst_*) or
        5 of ($str_posh_*) or
        6 of ($str_log_*)
}
