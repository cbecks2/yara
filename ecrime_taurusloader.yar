import "pe"

rule TaurusLoader
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-04-05"
        desc = "Detects Taurus Loader DLL."
        hash = "fd3f645c58ca9716d4437408d8283479526382fe5042aae6fa87ff2d8a4dd1be"
    condition:
         uint16(0) == 0x5A4D and (pe.characteristics & pe.DLL) and ( (pe.dll_name == "22.dll") or pe.exports("FileSeek16") or pe.exports("FileSeek32") or pe.imphash() == "8ffd5dcc30f824f746c3df4f59cc3f8a" ) and filesize < 5MB
}
