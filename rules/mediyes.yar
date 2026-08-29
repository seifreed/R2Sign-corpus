rule R2Sign_Generated {
    strings:
        $blob_0 = { c7 01 5c 42 02 64 e9 30 0e 01 00 cc cc cc cc cc 56 8b f1 c7 06 5c 42 02 64 e8 1d 0e 01 00 f6 44 }
        $blob_1 = { c7 01 5c 42 02 64 e9 30 0e 01 00 cc cc cc cc cc 56 8b f1 c7 06 5c 42 02 64 e8 1d 0e 01 00 f6 44 }
        $blob_2 = { c7 01 04 63 02 64 e9 20 28 01 00 cc cc cc cc cc 56 8b f1 c7 06 04 63 02 64 e8 0d 28 01 00 f6 44 }
    condition:
        any of them
}
