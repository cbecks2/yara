import "pe"

rule TaurusLoader
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-04-05"
        desc = "Detects Taurus Loader DLL."
        hash = "fd3f645c58ca9716d4437408d8283479526382fe5042aae6fa87ff2d8a4dd1be"

    strings:
        $0 = {83 7C 24 08 01 75 ?? 8B 44 24 04 A3 ?? ?? ?? 10 E8} // "PureBasic DLL -> Neil Hodgson"
        $1 = {68 ?? ?? 00 00 68 00 00 00 00 68 ?? ?? ?? 00 E8 ?? ?? ?? 00 83 C4 0C 68 00 00 00 00 E8 ?? ?? ?? 00 A3 ?? ?? ?? 00 68 00 00 00 00 68 00 10 00 00 68 00 00 00 00 E8 ?? ?? ?? 00 A3} // "PureBasic 4.x -> Neil Hodgson"
        $2 = {83 7C 24 08 01 75 0E 8B 44 24 04 A3 ?? ?? ?? 10 E8 22 00 00 00 83 7C 24 08 02 75 00 83 7C 24 08 00 75 05 E8 ?? 00 00 00 83 7C 24 08 03 75 00 B8 01 00 00 00 C2 0C 00 68 00 00 00 00 68 00 10 00 00 68 00 00 00 00 E8 ?? 0F 00 00 A3} // "PureBasic 4.x DLL -> Neil Hodgson"



    condition:
         uint16(0) == 0x5A4D
         and filesize < 5MB
         and ($0 at pe.entry_point or $1 at pe.entry_point or $2 at pe.entry_point)
         and pe.sections[0].name == ".code"
         and (pe.characteristics & pe.DLL)
         and ( 
             (pe.dll_name == "22.dll")
             or pe.exports("FileSeek16")
             or pe.exports("FileSeek32")
             or pe.imphash() == "8ffd5dcc30f824f746c3df4f59cc3f8a"
             )
}
