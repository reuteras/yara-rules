rule apt_ZZ_Sofacy_linkinfo_heur {
    meta:
		author = "Kasperksy Lab"
		type = "APT"
		description = "Find too old x64 PE samples"
        reference = "https://securelist.com/yara-webinar-follow-up/96505/"

    strings:
        $a1 = "CreateLinkInfo" fullword ascii
        $a2 = "CreateLinkInfoA" fullword ascii
        $a3 = "ResolveLinkInfo" fullword ascii
        $a4 = "ResolveLinkInfoA" fullword ascii
        $a5 = "GetCanonicalPathInfo" fullword ascii
        $a6 = "GetCanonicalPathInfoA" fullword ascii $a7 = "DisconnectLinkInfo" fullword ascii
        $a8 = "GetCanonicalPathInfoW" fullword ascii $a9 = "CompareLinkInfoVolumes" fullword ascii $a10 = "CompareLinkInfoReferents" fullword ascii $a11 = "ResolveLinkInfoW" fullword ascii
        $a12 = "GetLinkInfoData" fullword ascii
        $a13 = "linkinfo.dll" fullword ascii
        $a14 = "CreateLinkInfoW" fullword ascii
        $a15 = "DestroyLinkInfo" fullword ascii
        $a16 = "IsValidLinkInfo" fullword ascii
        $a17 = "HttpSendRequestExW" fullword ascii $a18 = ".?AV_Ref_count_base@tr1@std@@" fullword
        $a19 = "InternetQueryDataAvailable" fullword ascii $a20 = "HttpOpenRequestA" fullword ascii
        $a21 = "InternetConnectW" fullword ascii
        $a22 = "InternetOpenW" fullword ascii
        $a23 = "InternetReadFile" fullword ascii $a24 = "GetUserNameW" fullword ascii
        $a25 = "GetVolumeInformationW" fullword ascii $a26 = "SystemFunction036" fullword ascii $a27 = "lstrcatW" fullword ascii
        $a28 = "WININET.dll" fullword ascii
        $a29 = "ADVAPI32.DLL" fullword wide
        $a30 = "GetEnvironmentVariableW" fullword ascii $a31 = "GetExitCodeThread" fullword ascii
        $a32 = "TerminateThread" fullword ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 1000000 and
        28 of them // you can safely remove 4 garbage strings
}
