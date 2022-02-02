rule zip_unix_63_indrik_spider_feb_22
{
    meta:
        author = "@cbecks_2"
        version = "1.0"
        date = "2022-02-02"
        desc = "Detect zips created by unix v6.3 and out of the Indrik Spider Feb 2022 Campaign. Credit to Tyler McLellan for the base rule."
    strings:
        $header = {504B01023F0314}
        $a1 = {43 68 72 6f 6d 65 2e} //Chrome.
        $a2 = {46 69 72 65 66 6f 78 2e} //Firefox.
        $a3 = {45 64 67 65 2e} //Edge.
        $a4 = {64 6f 77 6e 6c 6f 61 64 2e} //download.
        $a5 = {44 6f 77 6e 6c 6f 61 64 2e} //Download.

        $ext = {2e 6a 73} //.js

    condition:
        uint16be(0) == 0x504B and @header[1] and filesize < 200KB and any of ($a*) and ($ext)

}
