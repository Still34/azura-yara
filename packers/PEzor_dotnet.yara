rule PEzor_dotnet {
    meta:
        author = "Still34"
        license = "GPL-3.0"
        component_name = "PEzor"
        create_date = "2021-08-05"
        description = "attempts to match the PEzor packer (dotnet)"
        last_modified = "2021-08-05"
        // compiled against a variety of packed hello world exe
        sample_hash = "N/A"
    strings:
        $pinvoke_1 = "VirtualProtectEx" wide
        $pinvoke_2 = "VirtualAlloc" wide
        $pinvoke_3 = "ZwMapViewOfSection" wide
        $pinvoke_4 = "LdrLoadDll" wide
        $method_1 = "LoadModuleFromDisk" ascii
        $dotnet_assembly = "System.Security.Permissions.SecurityPermissionAttribute" ascii
    condition:
        all of them
}
