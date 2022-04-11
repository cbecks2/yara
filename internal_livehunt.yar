import "vt"

rule mycompany_internal {
   meta:
      description = "Internal *My Company Here* Strings for Live and Retro Hunting"
      author = "@cbecks_2"
      reference = "Internal"
      date = "2022-04-10"
   strings:
   // Internal Domains (AD and web domains)
   // Could remove leading '.' but may lend false positives.
      $s1 = ".myinternaldomain.com" wide ascii
      $s2 = "subdomain.myinternaldomain.com" wide ascii
      $s3 = "mycompany.onmicrosoft.com" wide ascii
      $s4 = "myinternaldomain.sharepoint.com" wide ascii   

   // Email Addresses and UPNs
      $s5 = "@mydomain.com" wide ascii
      $s6 = "@subdomain.myinternaldomain.com" wide ascii

   // ProofPoint Secure Email
      $s7="securemail.mydomain.com" wide ascii
    
    // FPs
      $fp1="common false postive string" wide ascii
   		
      condition: 
      any of them and not vt.metadata.file_type == vt.FileType.JAVASCRIPT and not vt.metadata.file_type == vt.FileType.ANDROID and not $fp1
}
