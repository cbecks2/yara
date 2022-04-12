rule vuln_forshaw_1550_DefineDosDevice_LPE
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-04-12"
        desc = "Detects executables which may attempt to exploit James Forshaw's Issue 1550, which allows for Local Elevation of Privilege. Specifically, this rule looks at the original vulnerability and will also catch using this vulnerability to create a false KnownDLLs directory in order to achieve arbitrary DLL injection into services.exe, which runs as the highest level of PPL. This can be used to open handles to other processes at the same PPL level or lower, which could allow for the disablement of many EDR products."
        ref = "https://googleprojectzero.blogspot.com/2018/08/windows-exploitation-tricks-exploiting.html"

    strings:
        $a1 = "\\GLOBAL??\\KnownDlls" ascii wide nocase // \GLOBAL??\KnownDlls
        $a2 = "\\??\\GLOBALROOT" ascii wide nocase // \??\GLOBALROOT
        $a3 = "DefineDosDevice" ascii wide nocase
        $a4 = "\\??" ascii wide nocase
        

    condition:
         uint16(0) == 0x5A4D
         and filesize < 5MB
         and all of them
}
