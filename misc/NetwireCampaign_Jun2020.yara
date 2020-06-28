rule NetwireCampaign_MacroDoc_Jun2020{

    meta:
    	description = "Yara Rule for Netwire campaign macro document Jun2020"
    	author = "Cybaze Zlab_Yoroi"
 		last_updated = "2020-06-05"
		tlp = "white"
		SHA256 = "b7e95d0dcedd77ab717a33163af23ab2fd2dc6d07cdf81c5e4cfe080b0946b79"
		category = "informational"
		url = "https://yoroi.company/research/new-cyber-operation-targets-italy-digging-into-the-netwire-attack-chain/"

    strings:
    	$a1 = {D9 CB 86 F2 BB BE 2F 61 57}
       	$a2 = {70 E0 C0 81 03 07 0E 1C}
        $a3 = {4F 8B D2 E4 EF EE 50 9A 5C 2E} 

	condition:
    	all of them
}

rule NetwireCampaign_Payload_Jun2020{

    meta:
		description = "Yara Rule for Netwire campaign final payload Jun2020"
		author = "Cybaze Zlab_Yoroi"
		last_updated = "2020-06-05"
		tlp = "white"
		SHA256 = "cc419a1c36ed5bdae1d3cd35c4572766dc06ad5a447687f87e89da0bb5a42091"
		category = "informational"
		url = "https://yoroi.company/research/new-cyber-operation-targets-italy-digging-into-the-netwire-attack-chain/"

    strings:
		$a1 = {c7 04 ?4 ?? ?? ?? ?? e8 6f 2c 00 00 c7 04 ?4 ?? ?? ?? ?? e8 63 2c 00 00 8b 35}
       	$a2 = {89 84 ?4 b0 00 00 00 c7 84 ?4 a4 00 00 00 ?? ?? ?? ?? 66 c7 84 ?4 a8 00 00 00 00 00 e8 ?? ?? ?? ?? 83 ec 28 85 c0 75 27}
        $a3 = { c7 44 ?4 0c ?? ?? ?? ?? c7 44 ?4 08 ?? ?? ?? ?? c7 04 ?4 ?? ?? ?? ?? 89 44 ?4 04 e8 39 1c 01 00 83 ec ??  } 

    condition:
        uint16(0) == 0x5A4D and 2 of ($a*)
}
