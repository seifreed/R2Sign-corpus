rule R2SignMediyesVxSig {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         8b4424148946088b7e0c85ff8b4c241c894c24187414
         // 64001561: MOV EAX, [ESP+0x14]
         // 64001565: MOV [ESI+0x8], EAX
         // 64001568: MOV EDI, [ESI+0xc]
         // 6400156b: TEST EDI, EDI
         // 6400156d: MOV ECX, [ESP+0x1c]
         // 64001571: MOV [ESP+0x18], ECX
         // 64001575: JZ 0x6400158b
      [-]ffd35789442418ffd58b54241452ff15
         // 64001577: CALL EBX
         // 64001579: PUSH EDI
         // 6400157a: MOV [ESP+0x18], EAX
         // 6400157e: CALL EBP
         // 64001580: MOV EDX, [ESP+0x14]
         // 64001584: PUSH EDX
         // 64001585: CALL [0x64026060]
      [-]0fb7f86a0057e8
         // 64002785: MOVZX EDI, AX
         // 64002788: PUSH 0x0
         // 6400278a: PUSH EDI
         // 6400278b: CALL 0x64001fa0
      [-]02648d4c243451e8
         // 64003541: LEA ECX, [ESP+0x34]
         // 64003545: PUSH ECX
         // 64003546: CALL 0x64013b5b
      [-]83c0013dffffff3f7e04
         // 6400385a: ADD EAX, 0x1
         // 6400385d: CMP EAX, 0x3fffffff
         // 64003862: JLE 0x64003868
      [-]c78424????????ffffffff397c2460c74424340f000000895c2430885c2420720d
         // 64003d3e: MOV [ESP+0x478], 0xffffffff
         // 64003d49: CMP [ESP+0x60], EDI
         // 64003d4d: MOV [ESP+0x34], 0xf
         // 64003d55: MOV [ESP+0x30], EBX
         // 64003d59: MOV b1 [ESP+0x20], BL
         // 64003d5d: JC 0x64003d6c
      [-]8b01385829750f
         // 64003d93: MOV EAX, [ECX]
         // 64003d95: CMP b1 [EAX+0x29], BL
         // 64003d98: JNZ 0x64003da9
      [-]0000c645fc02397df0720c
         // 64003ffa: MOV b1 [EBP+0xfffffffffffffffc], 0x2
         // 64003ffe: CMP [EBP+0xfffffffffffffff0], EDI
         // 64004001: JC 0x6400400f
      [-]8970f48b0f66c7047100005e8bc75bc3
         // 640066c6: MOV [EAX+0xfffffffffffffff4], ESI
         // 640066c9: MOV ECX, [EDI]
         // 640066cb: MOV b2 [ECX+ESI*0x2], 0x0
         // 640066d1: POP ESI
         // 640066d2: MOV EAX, EDI
         // 640066d4: POP EBX
         // 640066d5: RET 
      [-]8b47148b7424182bc53bc67302
         // 640071b4: MOV EAX, [EDI+0x14]
         // 640071b7: MOV ESI, [ESP+0x18]
         // 640071bb: SUB EAX, EBP
         // 640071bd: CMP EAX, ESI
         // 640071bf: JNC 0x640071c3
      [-]8b4500eb02
         // 64007488: MOV EAX, [EBP]
         // 6400748b: JMP 0x6400748f
      [-]3bfb0f95c085c0
         // 64008bd6: CMP EDI, EBX
         // 64008bd8: SETNZ AL
         // 64008bdb: TEST EAX, EAX
      [-]8b4604807845007510
         // 6400921f: MOV EAX, [ESI+0x4]
         // 64009222: CMP b1 [EAX+0x45], 0x0
         // 64009226: JNZ 0x64009238
      [-]399c24????????7e07
         // 6400a89f: CMP [ESP+0x100a8], EBX
         // 6400a8a6: JLE 0x6400a8af
      [-]8b3385f6743e
         // 6400abbe: MOV ESI, [EBX]
         // 6400abc0: TEST ESI, ESI
         // 6400abc2: JZ 0x6400ac02
      [-]2bc5c6043800
         // 6400b0b5: SUB EAX, EBP
         // 6400b0b7: MOV b1 [EAX+EDI*0x1], 0x0
      [-]558bec83e4f8b8342f0000e8
         // 6400b0d0: PUSH EBP
         // 6400b0d1: MOV EBP, ESP
         // 6400b0d3: AND ESP, 0xfffffff8
         // 6400b0d6: MOV EAX, 0x2f34
         // 6400b0db: CALL 0x64019860
      [-]8bc6c745d80f000000c745d400000000c645c4008d5001
         // 6400b42d: MOV EAX, ESI
         // 6400b42f: MOV [EBP+0xffffffffffffffd8], 0xf
         // 6400b436: MOV [EBP+0xffffffffffffffd4], 0x0
         // 6400b43d: MOV b1 [EBP+0xffffffffffffffc4], 0x0
         // 6400b441: LEA EDX, [EAX+0x1]
      [-]000083c404
         // 6400b90d: ADD ESP, 0x4
      [-]02646a0b68
         // 6400e125: PUSH 0xb
         // 6400e127: PUSH 0x6402a684
      [-]ffff83c414508d4de8e8
         // 6401259c: ADD ESP, 0x14
         // 6401259f: PUSH EAX
         // 640125a0: LEA ECX, [EBP+0xffffffffffffffe8]
         // 640125a3: CALL 0x640065a0
      [-]23000085c0597403
         // 64013ab2: TEST EAX, EAX
         // 64013ab4: POP ECX
         // 64013ab5: JZ 0x64013aba
      [-]03648b44241c59eb02
         // 64014025: MOV EAX, [ESP+0x1c]
         // 64014029: POP ECX
         // 6401402a: JMP 0x6401402e
      [-]a90000ff007413
         // 64015783: TEST EAX, 0xff0000
         // 64015788: JZ 0x6401579d
      [-]0264ff15??
         // 64015e21: CALL [0x64026124]
      [-]8b4424085ec3
         // 64015ec7: MOV EAX, [ESP+0x8]
         // 64015ecb: POP ESI
         // 64015ecc: RET 
      [-]568bf1c706
         // 640163d8: PUSH ESI
         // 640163d9: MOV ESI, ECX
         // 640163db: MOV [ESI], 0x64026d48
      [-]837e10030f857e010000
         // 64016d8c: CMP [ESI+0x10], 0x3
         // 64016d90: JNZ 0x64016f14
      [-]66c745bc2b00eb0a
         // 640189e6: MOV b2 [EBP+0xffffffffffffffbc], 0x2b
         // 640189ec: JMP 0x640189f8
      [-]a8017406
         // 6401ab82: TEST AL, 0x1
         // 6401ab84: JZ 0x6401ab8c
      [-]558bec83ec205333db395d147520
         // 6401acf5: PUSH EBP
         // 6401acf6: MOV EBP, ESP
         // 6401acf8: SUB ESP, 0x20
         // 6401acfb: PUSH EBX
         // 6401acfc: XOR EBX, EBX
         // 6401acfe: CMP [EBP+0x14], EBX
         // 6401ad01: JNZ 0x6401ad23
      [-]8b45108903894418fc
         // 6401bd76: MOV EAX, [EBP+0x10]
         // 6401bd79: MOV [EBX], EAX
         // 6401bd7b: MOV [EAX+EBX*0x1+0xfffffffffffffffc], EAX
      [-]8b4a043b4a08755c
         // 6401bf17: MOV ECX, [EDX+0x4]
         // 6401bf1a: CMP ECX, [EDX+0x8]
         // 6401bf1d: JNZ 0x6401bf7b
      [-]040000b9010000008b4308e8
         // 6401c423: MOV ECX, 0x1
         // 6401c428: MOV EAX, [EBX+0x8]
         // 6401c42b: CALL 0x6401c880
      [-]3c00005f5e5b5dc3
         // 6401c4e7: POP EDI
         // 6401c4e8: POP ESI
         // 6401c4e9: POP EBX
         // 6401c4ea: POP EBP
         // 6401c4eb: RET 
      [-]3bfb7452
         // 6401f07b: CMP EDI, EBX
         // 6401f07d: JZ 0x6401f0d1
      [-]381f8bcf7413
         // 6402023a: CMP b1 [EDI], BL
         // 6402023c: MOV ECX, EDI
         // 6402023e: JZ 0x64020253
      [-]8bc64639551489450c7504
         // 640209f5: MOV EAX, ESI
         // 640209f7: INC ESI
         // 640209f8: CMP [EBP+0x14], EDX
         // 640209fb: MOV [EBP+0xc], EAX
         // 640209fe: JNZ 0x64020a04
      [-]8b4dfc5f5e33cd5be8
         // 64020d76: MOV ECX, [EBP+0xfffffffffffffffc]
         // 64020d79: POP EDI
         // 64020d7a: POP ESI
         // 64020d7b: XOR ECX, EBP
         // 64020d7d: POP EBX
         // 64020d7e: CALL 0x64013f6c
      [-]2ac33c098975a40f876effffff
         // 6402211f: SUB AL, BL
         // 64022121: CMP AL, 0x9
         // 64022123: MOV [EBP+0xffffffffffffffa4], ESI
         // 64022126: JA 0x6402209a
      [-]8d4df0e9
         // 64023781: LEA ECX, [EBP+0xfffffffffffffff0]
         // 64023784: JMP 0x64001680

  }
  condition:
    all of them
}

