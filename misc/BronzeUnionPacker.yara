import "pe"
rule BronzeUnionPacker {
    meta:
        url = "https://www.blackberry.com/content/dam/blackberry-com/asset/enterprise/pdf/direct/report-bb-decade-of-the-rats.pdf"
    condition:
        pe.timestamp == 12345 and for any i in (0..pe.number_of_sections - 1):
            (pe.sections[i].name == ".UPX0") and pe.number_of_signatures >= 1
}
