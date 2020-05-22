rule apt_custom_packer {
    meta:
        description = "Detects the beginning of the actors packer"
        url = "https://labs.sentinelone.com/the-anatomy-of-an-apt-attack-and-cobaltstrike-beacons-encoded-configuration/"
    strings:
        $b1 = {C7 44 24 38 53 56 43 48}
        $b2 = {C7 44 24 3C 4F 53 54 2E}
        $b3 = "exampleMu"
    condition:
        (uint16(0) == 0x5a4d) and all of ($b*)
}
