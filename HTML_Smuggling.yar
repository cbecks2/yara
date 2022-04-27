rule HTML_Smuggling {
    meta:
        description = "Created to detect possible smuggling of an ISO, ZIP, VHD, or VHDX inside of an HTML attachment. Sometimes it will also catch an HTML dropper."
        author = "@cbecks_2"
        reference = "Various HTML Smuggling Attempts"
        date = "2022-04-27"
        hash1 = "6d12f55bc1fa3a33445417245a8ef5f2685c5f0eadf98a9d90fbdbd442c5eac4"
        hash2 = "b60bd26f13ef5b4d42ca3400291af2b4a44360ecbf9cc3a2aa82aa9b6b6bd916"
        hash3 = "a0f3381aeab53548f79fe66e8e997cf72aa543bbfad816db36d528dde6037c8c"
        hash4 = "bba30bf53f7e88310b4c37553b6de92d061fea28545b51fb000a29c234a69509"
        hash5 = "deb3fab2541beb78db8ef42ebe74732f7720b1a77b9e58b37f632260628dade7"

    strings:
        $a1 = "<html" ascii
        $a2 = "<body>" ascii
        $a3 = "<script" ascii
        $a4 = "</script>" ascii
        $a5 = "</body>" ascii
        $a6 = "</html>" ascii
        
        $b1 = ".ISO\"" ascii wide nocase
        $b2 = "CD001" base64 base64wide // this may get some false positives due to string length
        $b3 = { 43 44 30 30 31 } // hex of CD001
        $b4 = ".vhd\"" ascii wide nocase
        $b5 = "conectix" base64 base64wide // ascii in VHD File Signature
        $b6 = { 63 6F 6E 65 63 74 69 78 } // hex of VHD File Signature
        $b7 = "vhdxfile" base64 base64wide // ascii in VHDX File Signature
        $b8 = { 76 68 64 78 66 69 6C 65 } // hex of VHDX of File Signature
        $b9 = { 50 4B 03 04 } //zip
        $b10 = "UEsDBB" // base64 representation of 504B0404 (zip)
        $b11 = { 50 4B 4C 49 54 45 } //zip
        $b12 = "UEtMSVRF" // base64 representation of 504B4C495445 (zip)
        $b13 = { 50 4B 53 70 05 } //zip
        $b14 = "UEtTcAU" // base64 representation of 504B537005 (zip)
        $b15 = { 50 4b 05 06 } //zip
        $b16 = "UEsFBg" // base64 representation of 504B0506 (zip)
        $b17 = { 50 4b 07 08 } //zip
        $b18 = "UEsHCA" //base64 representation of 404B0708 (zip)
        $b19 = { 57 69 6e 5a 69 70 }
        $b20 = "V2luWmlw" // base64 representation of 57696E5A6970 (zip)


        $c1 = "The file has been uploaded successfully," ascii
        $c2 = "this.base64ToBlob = base64ToBlob;" ascii
        $c3 = "a.href = window.URL.createObjectURL(blob, {type: \"application/octet-stream\"});" ascii
        $c4 = "System.Threading.Thread" base64 base64wide
        $c5 = ".vbs" base64 base64wide
        $c6 = ".VBS" base64 base64wide
        $c7 = ".js" base64 base64wide
        $c8 = ".JS" base64 base64wide
        $c9 = ".lnk" base64 base64wide
        $c10 = ".LNK" base64 base64wide
        $c11 = ".hta" base64 base64wide
        $c12 = ".HTA" base64 base64wide
        $c13 = ".exe" base64 base64wide
        $c14 = ".EXE" base64 base64wide
        $c15 = ".zip" base64 base64wide
        $c16 = ".ZIP" base64 base64wide
        $c17 = "    var data =" ascii
        $c18 = "var text =" ascii
        $c19 = "DropFileName = \"" ascii
        $c20 = "4D5A" ascii wide nocase
        $c21 = "4D5A" base64 base64wide

      
    condition:
        filesize < 5MB and all of ($a*) and any of ($b*) and any of ($c*)
}
