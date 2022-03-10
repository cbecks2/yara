import "pe"

rule sus_hacktool_ppldump_dll_name
{
    meta:
    author = "@cbecks_2"
    version = "1.0"
    date = "2022-03-10"
    desc = "This rule looks for the pe.dll_name harcoded as PPLdumpDLL.dll, which could be indicative of source code used or stolen from the PPLdump project. All hits are suspicious."
    reference = "https://github.com/itm4n/PPLdump"

    condition:
         uint16(0) == 0x5a4d and (pe.dll_name icontains "PPLdumpDLL.dll")
}
