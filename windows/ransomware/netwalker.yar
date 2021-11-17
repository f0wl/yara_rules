rule Netwalker : ransomware { 
  meta: 
    description = "Detects Netwalker Ransomware" 
    author = "Marius 'f0wL' Genheimer <hello@dissectingmalwa.re>" 
    reference = "https://github.com/f0wl/configwalker" 
    date = "2020-10-26" 
    hash1 = "4f7bdda79e389d6660fca8e2a90a175307a7f615fa7673b10ee820d9300b5c60"
    hash2 = "46dbb7709411b1429233e0d8d33a02cccd54005a2b4015dcfa8a890252177df9"
    hash3 = "5d869c0e077596bf0834f08dce062af1477bf09c8f6aa0a45d6a080478e45512"

  strings: 
    $conf1 = "svcwait" fullword ascii
    $conf2 = "mscfile" fullword wide
    $conf3 = "pspath" fullword ascii
    $conf4 = "extfree" fullword ascii
    $conf5 = "encname" fullword ascii
    $conf6 = "mode" fullword ascii
    $conf7 = "spsz" fullword ascii
    $conf8 = "idsz" fullword ascii
    $conf9 = "onion1" fullword ascii
    $conf10 = "onion2" fullword ascii
    $conf11 = "lfile" fullword ascii
    $conf12 = "lend" fullword ascii
    $conf13 = "white" fullword ascii
    $conf14 = "path" fullword ascii
    $conf15 = "file" fullword ascii
    $conf16 = "extfree" fullword ascii
    $conf17 = "kill" fullword ascii
    $conf18 = "svcwait" fullword ascii
    $conf19 = "task" fullword ascii
    $conf20 = "ignore" fullword ascii
    $conf21 = "disk" fullword ascii
    $conf22 = "share" fullword ascii
    $conf23 = "unlock" fullword ascii
    $conf24 = "pspath" fullword ascii
    $conf25 = "encname" fullword ascii
    
    $s1 = "taskkill /F /PID" fullword ascii
    $s2 = "{code_id:" ascii
    $s3 = "{id}-Readme.txt" fullword wide
    $s4 = "netwalker" fullword wide
    $s5 = "expand 16-byte k" fullword ascii
    $s6 = "InterfacE\\{b196b287-bab4-101a-b69c-00aa00341d07}" fullword ascii
      
  condition: 
    uint16(0) == 0x5a4d 
    and filesize < 10000KB 
    and (7 of ($conf*)) or (2 of ($s*))
}
