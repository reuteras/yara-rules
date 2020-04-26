import "pe"
rule susp_too_old_x64_PE_samples {
    meta:
		author = "Kasperksy Lab"
		type = "APT"
		description = "Find too old x64 PE samples"
        reference = "https://securelist.com/yara-webinar-follow-up/96505/"

    condition:
	    uint16(0) == 0x5A4D
	    and (pe.machine == pe.MACHINE_AMD64
	    or pe.machine == pe.MACHINE_IA64)
	    and pe.timestamp > 631155661 // 1990-01-01
	    and pe.timestamp < 1072915200 // 2004-01-01 and filesize < 2000000
}
