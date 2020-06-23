rule apt_ZZ_Naikon_codebase : Naikon
{
    meta:
        report = "Naikon New AR Backdoor Deployment to Southeast Asia"
        description = "Naikon typo"
        author = "Kaspersky"
        copyright = "Kaspersky"
        version = "1.0"
        date = "2018-06-28"
        last_modified = "2018-06-28"
        url = "https://securelist.com/naikons-aria/96899/"

    strings:
        $a1 = "Create Directroy [%s] Failed:%d" wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 450000 and
        $a1
}
