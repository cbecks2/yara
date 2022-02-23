rule csv_launcher_feb22 {

    meta:  
        description = "Detects xls documents that are formatted in such a way that causes the document to launch a command."
        author = "@cbecks_2"
        reference1 = "85b1922967d4741eaaf1bc46bc394f39cf50f1fcc238326e22ea9410844087dc"
        reference2 = "https://twitter.com/phage_nz/status/1488310674279530496, 85b1922967d4741eaaf1bc46bc394f39cf50f1fcc238326e22ea9410844087dc"
        reference3 = "https://isc.sans.edu/forums/diary/Developing+YARA+Rules+a+Practical+Example/24158/"
        reference4 = "https://www.virustotal.com/gui/search/comment%253A%2522SUSP_PS1_Flags_Indicator_Feb22_1%2522/files"
        tlp = "white"  
        date = "2022-02-23"  
    
	strings:
        $a = /(^|\n|,|\s)=(\s|\S)*cmd\|/ nocase
        $b = /(^|\n|,|\s)=(\s|\S)*powershell\|/ nocase
        $c = /(^|\n|,|\s)=(\s|\S)*pwsh\|/ nocase
        $d = /(^|\n|,|\s)=(\s|\S)*wscript\|/ nocase
        $e = /(^|\n|,|\s)=(\s|\S)*cscript\|/ nocase
        $f = /(^|\n|,|\s)=(\s|\S)*certutil\|/ nocase
        $g = /(^|\n|,|\s)=(\s|\S)*wmic\|/ nocase

	condition:
		any of them and filesize < 1000KB 
}
