import "pe"
rule BronzeUnionPacker {
	condition:
		pe.timestamp == 12345 and for any i in (0..pe.number_of_sections - 1):
		    (pe.sections[i].name == ".UPX0") and pe.number_of_signatures >= 1
}
