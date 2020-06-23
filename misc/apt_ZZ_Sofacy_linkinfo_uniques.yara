rule apt_ZZ_Sofacy_linkinfo_uniques {
    meta:
        author = "Kasperksy Lab"
        type = "APT"
        description = "Find too old x64 PE samples"
        reference = "https://securelist.com/yara-webinar-follow-up/96505/"

    strings:
        $a1 = "unsuccess&nbsp:&nbsp" fullword wide
        $a2 = "ReleaseMutex error!" fullword ascii
        $a3 = "<3tm<4ti<5te<6ta" fullword ascii
        $a4 = "Active Acceessibility Resource File" fullword wide
        $a5 = "11.0.4621.4331splm.dll" fullword wide
        $a6 = "13.5.6765.37769" fullword wide
        $a7 = "11.0.4621.4331" fullword wide
        $a8 = "5.1.2600.2185" fullword wide

   condition:
        uint16(0) == 0x5A4D and
        filesize < 1000000 and
        2 of them // any of these strings is unique but better to use 2
}
