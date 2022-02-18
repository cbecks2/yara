rule azure_information_protection_encrypted_file.yar {  
       
   meta:  
        description = "Detects documents encrypted by Azure Information Protection (AIP)"
        author = "@cbecks_2"  
        reference = ""
        tlp = "white"  
        date = "2022-02-18"  
    
    strings:
        $string1 = "type=\"Microsoft Rights Label\"" ascii nocase
        $string2 = "DESCRIPTION Permission is currently restricted. Only specified users can access this content." ascii nocase
   
   condition:  
        all of them
    
   }
