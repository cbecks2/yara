rule HTML_Smuggling {
    meta:
        description = "Created to detect possible smuggling of an ISO inside of an HTML attachment. Sometimes it will also catch other HTML droppers."
        author = "@cbecks_2"
        reference = "ASyncRat January 2022"
        date = "2022-01-05"
        hash1 = "6d12f55bc1fa3a33445417245a8ef5f2685c5f0eadf98a9d90fbdbd442c5eac4"
        hash2 = "b60bd26f13ef5b4d42ca3400291af2b4a44360ecbf9cc3a2aa82aa9b6b6bd916"
        hash3 = "a0f3381aeab53548f79fe66e8e997cf72aa543bbfad816db36d528dde6037c8c"
        hash4 = "bba30bf53f7e88310b4c37553b6de92d061fea28545b51fb000a29c234a69509"

    strings:
        $a1 = "<html" ascii
        $a2 = "<body>" ascii
        $a3 = "<script>" ascii
        $a4 = "</script>" ascii
        $a5 = "</body>" ascii
        $a6 = "</html>" ascii
        
        $b1 = ".ISO" ascii
        $b2 = "CD001" base64 base64wide // this may get some false positives, and smuggled .exes due to string length
        $b3 = { 43 44 30 30 31 } // hex of CD001

        $c1 = "The file has been uploaded successfully," ascii
        $c2 = "this.base64ToBlob = base64ToBlob;" ascii
        $c3 = "a.href = window.URL.createObjectURL(blob, {type: \"application/octet-stream\"});" ascii
        $c4 = "System.Threading.Thread" base64 base64wide
        $c5 = ".vbs" base64 base64wide
        $c6 = ".js" base64 base64wide
        $c7 = ".lnk" base64 base64wide
        $c8 = ".hta" base64 base64wide
        $c9 = ".exe" base64 base64wide
        $c10 = "    var data =" ascii
        $c11 = "DropFileName = \"" ascii
        $c12 = "4D5A" ascii wide nocase
        $c13 = "4D5A" base64 base64wide

    condition:
        filesize < 500KB and all of ($a*) and any of ($b*) and any of ($c*)
}
