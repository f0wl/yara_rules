rule EzuriLoader_revised : LinuxMalware {

    meta:
        author = "Marius 'f0wL' Genheimer, https://dissectingmalwa.re"
        description = "Detects Ezuri Golang Loader/Crypter"
        reference = "https://cybersecurity.att.com/blogs/labs-research/malware-using-new-ezuri-memory-loader"
        date = "09.01.2021"
        tlp = "WHITE"
        hash1 = "ddbb714157f2ef91c1ec350cdf1d1f545290967f61491404c81b4e6e52f5c41f"
        hash2 = "751014e0154d219dea8c2e999714c32fd98f817782588cd7af355d2488eb1c80"

    strings:

        // This is a revised rule originally created by AT&T alien labs
        $a1 = "main.runFromMemory"
        $a2 = "main.aesDec"
        $a3 = "crypto/cipher.NewCFBDecrypter"
        $a4 = "/proc/self/fd/%d"
        $a5 = "/dev/null"

    condition:
        uint32(0) == 0x464c457f and
        filesize < 20MB and all of ($a*)
} 
