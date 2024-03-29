rule win_cobalt_strike_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-06-10"
        version = "1"
        description = "Detects win.cobalt_strike."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike"
        malpedia_rule_date = "20210604"
        malpedia_hash = "be09d5d71e77373c0f538068be31a2ad4c69cfbd"
        malpedia_version = "20210616"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    /* DISCLAIMER
     * The strings used in this rule have been automatically selected from the
     * disassembly of memory dumps and unpacked files, using YARA-Signator.
     * The code and documentation is published here:
     * https://github.com/fxb-cocacoding/yara-signator
     * As Malpedia is used as data source, please note that for a given
     * number of families, only single samples are documented.
     * This likely impacts the degree of generalization these rules will offer.
     * Take the described generation method also into consideration when you
     * apply the rules in your use cases and assign them confidence levels.
     */


    strings:
        $sequence_0 = { e9???????? eb0a b801000000 e9???????? }
            // n = 4, score = 1400
            //   e9????????           |                     
            //   eb0a                 | jmp                 0xc
            //   b801000000           | mov                 eax, 1
            //   e9????????           |                     

        $sequence_1 = { 3bc7 750d ff15???????? 3d33270000 }
            // n = 4, score = 1400
            //   3bc7                 | cmp                 eax, edi
            //   750d                 | jne                 0xf
            //   ff15????????         |                     
            //   3d33270000           | cmp                 eax, 0x2733

        $sequence_2 = { e9???????? 833d????????01 7505 e8???????? }
            // n = 4, score = 1000
            //   e9????????           |                     
            //   833d????????01       |                     
            //   7505                 | jne                 7
            //   e8????????           |                     

        $sequence_3 = { 8bd0 e8???????? 85c0 7e0e }
            // n = 4, score = 1000
            //   8bd0                 | mov                 edx, eax
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7e0e                 | jle                 0x10

        $sequence_4 = { 8b7510 57 56 893b e8???????? ff75fc }
            // n = 6, score = 900
            //   8b7510               | mov                 esi, dword ptr [ebp + 0x10]
            //   57                   | push                edi
            //   56                   | push                esi
            //   893b                 | mov                 dword ptr [ebx], edi
            //   e8????????           |                     
            //   ff75fc               | push                dword ptr [ebp - 4]

        $sequence_5 = { e8???????? 3945fc 74f2 8b45f4 3945f8 74c8 03db }
            // n = 7, score = 900
            //   e8????????           |                     
            //   3945fc               | cmp                 dword ptr [ebp - 4], eax
            //   74f2                 | je                  0xfffffff4
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   3945f8               | cmp                 dword ptr [ebp - 8], eax
            //   74c8                 | je                  0xffffffca
            //   03db                 | add                 ebx, ebx

        $sequence_6 = { ff75fc ff75f8 ff75f0 e8???????? 83c410 e8???????? 8bf7 }
            // n = 7, score = 900
            //   ff75fc               | cmp                 eax, edi
            //   ff75f8               | jne                 0xf
            //   ff75f0               | cmp                 eax, 0x2733
            //   e8????????           |                     
            //   83c410               | jmp                 0xc
            //   e8????????           |                     
            //   8bf7                 | mov                 eax, 1

        $sequence_7 = { 8b45f8 83c001 8945f8 837df807 7502 }
            // n = 5, score = 900
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   83c001               | add                 eax, 1
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   837df807             | cmp                 dword ptr [ebp - 8], 7
            //   7502                 | jne                 4

        $sequence_8 = { e8???????? 33f6 39750c 7e27 ff7508 ff15???????? 85c0 }
            // n = 7, score = 900
            //   e8????????           |                     
            //   33f6                 | xor                 esi, esi
            //   39750c               | cmp                 dword ptr [ebp + 0xc], esi
            //   7e27                 | jle                 0x29
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_9 = { 8b45f8 8345fc04 83c40c 43 }
            // n = 4, score = 900
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   8345fc04             | add                 dword ptr [ebp - 4], 4
            //   83c40c               | add                 esp, 0xc
            //   43                   | inc                 ebx

        $sequence_10 = { e8???????? e9???????? 488d5538 418bca e8???????? e9???????? 418b09 }
            // n = 7, score = 500
            //   e8????????           |                     
            //   e9????????           |                     
            //   488d5538             | dec                 eax
            //   418bca               | lea                 edx, dword ptr [ebp + 0x38]
            //   e8????????           |                     
            //   e9????????           |                     
            //   418b09               | inc                 ecx

        $sequence_11 = { e8???????? e9???????? 83fd03 7513 4c8bc7 }
            // n = 5, score = 500
            //   e8????????           |                     
            //   e9????????           |                     
            //   83fd03               | cmp                 ebx, 2
            //   7513                 | jb                  0x25
            //   4c8bc7               | mov                 eax, esi

        $sequence_12 = { e8???????? e9???????? 8364242000 ebc8 8bce 488d5530 895d30 }
            // n = 7, score = 500
            //   e8????????           |                     
            //   e9????????           |                     
            //   8364242000           | mov                 ecx, edx
            //   ebc8                 | inc                 ecx
            //   8bce                 | mov                 ecx, dword ptr [ecx]
            //   488d5530             | and                 dword ptr [esp + 0x20], 0
            //   895d30               | jmp                 0xffffffca

        $sequence_13 = { e8???????? e9???????? 83fb02 7223 }
            // n = 4, score = 500
            //   e8????????           |                     
            //   e9????????           |                     
            //   83fb02               | je                  0xcf
            //   7223                 | cmp                 ecx, 9

        $sequence_14 = { e8???????? e9???????? 8b01 6bc01c }
            // n = 4, score = 500
            //   e8????????           |                     
            //   e9????????           |                     
            //   8b01                 | dec                 esp
            //   6bc01c               | mov                 eax, edi

        $sequence_15 = { e8???????? e9???????? 83f908 0f84c6000000 }
            // n = 4, score = 500
            //   e8????????           |                     
            //   e9????????           |                     
            //   83f908               | mov                 ecx, esi
            //   0f84c6000000         | dec                 eax

    condition:
        7 of them and filesize < 696320
}