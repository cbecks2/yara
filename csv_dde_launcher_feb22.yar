import "vt"

rule csv_launcher_feb22 {

    meta:  
        description = "Detects xls documents that are formatted in such a way that causes the document to launch a command."
        author = "@cbecks_2"
        reference1 = "85b1922967d4741eaaf1bc46bc394f39cf50f1fcc238326e22ea9410844087dc"
        reference2 = "https://twitter.com/phage_nz/status/1488310674279530496, 85b1922967d4741eaaf1bc46bc394f39cf50f1fcc238326e22ea9410844087dc"
        reference3 = "https://isc.sans.edu/forums/diary/Developing+YARA+Rules+a+Practical+Example/24158/"
        reference4 = "https://www.virustotal.com/gui/search/comment%253A%2522SUSP_PS1_Flags_Indicator_Feb22_1%2522/files"
	reference5 = "https://blog.reversinglabs.com/blog/cvs-dde-exploits-and-obfuscation"
	reference6 = "https://valhalla.nextron-systems.com/info/rule/SUSP_EXPL_MsOffice_CSV_Feb22_1
        tlp = "white"  
        date = "2022-02-23"  
    
	strings:
        $a1 = /(^|\n|,|\s)=(\s|\S)*cmd\S*\|/ nocase
        $a2 = /(^|\n|,|\s)=(\s|\S)*powershell\S*\|/ nocase
        $a3 = /(^|\n|,|\s)=(\s|\S)*pwsh\S*\|/ nocase
        $a4 = /(^|\n|,|\s)=(\s|\S)*wscript\S*\|/ nocase
        $a5 = /(^|\n|,|\s)=(\s|\S)*cscript\S*\|/ nocase
        $a6 = /(^|\n|,|\s)=(\s|\S)*certutil\S*\|/ nocase
        $a7 = /(^|\n|,|\s)=(\s|\S)*wmic\S*\|/ nocase
        $a8 = /(^|\n|,|\s)=(\s|\S)*rundll32\S*\|/ nocase
        $a9 = /(^|\n|,|\s)=(\s|\S)*regsvr32\S*\|/ nocase
        $a10 = /(^|\n|,|\s)=(\s|\S)*msexcel\S*\|/ nocase
        $a11 = /(^|\n|,|\s)=(\s|\S)*msiexec\S*\|/ nocase
        
        $js1 = "document.getElementById" wide ascii nocase
        $js2 = ".createElement" wide ascii nocase
        $js3 = "function ()" wide ascii nocase
        $js4 = "navigator.userAgent" wide ascii nocase
        $html1 = "<DOCTYPE html>" wide ascii nocase
        $epub1 = "mimetypeapplication/epub" wide ascii nocase

	condition:
		any of them and filesize < 1000KB and (vt.metadata.file_type == vt.FileType.TEXT or vt.metadata.file_type == vt.FileType.JAVASCRIPT) and not any of ($js*) and not $html1 and not $epub1
        
}
