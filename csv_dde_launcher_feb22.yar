rule csv_dde_launcher_feb22 {

    meta:  
        description = "Detects xls documents that are formatted in such a way that causes the document to launch a command via DDE."
        author = "@cbecks_2, credit to Didier Stevens and Xme"
        reference1 = "85b1922967d4741eaaf1bc46bc394f39cf50f1fcc238326e22ea9410844087dc"
        reference2 = "https://twitter.com/phage_nz/status/1488310674279530496, 85b1922967d4741eaaf1bc46bc394f39cf50f1fcc238326e22ea9410844087dc"
        reference3 = "https://isc.sans.edu/forums/diary/Developing+YARA+Rules+a+Practical+Example/24158/"
        reference4 = "https://www.virustotal.com/gui/search/comment%253A%2522SUSP_PS1_Flags_Indicator_Feb22_1%2522/files"
        tlp = "white"  
        date = "2022-02-23"  
    
	strings:
        $a = /=(\s|\S)*cmd\|/ nocase
        $b = /=(\s|\S)*powershell\|/ nocase
        $c = /=(\s|\S)*pwsh\|/ nocase
        $d = /=(\s|\S)*wscript\|/ nocase
        $e = /=(\s|\S)*cscript\|/ nocase
        $f = /=(\s|\S)*certutil\|/ nocase
        $g = /=(\s|\S)*wmic\|/ nocase

	condition:
		any of them and filesize < 1000KB 
}
