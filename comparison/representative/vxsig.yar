rule R2Sign_fakeav_VxSig {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         8bff558bec83ec
         // 004d0040: mov edi, edi
         // 004d0042: push ebp
         // 004d0043: mov ebp, esp
         // 004d0045: sub esp, 0x50
      [-]204d008b
         // 004d0075: mov ecx, GetModuleHandleA
         // 004d007a: mov ecx, ds:[ecx]
      [-]5effd683c4
         // 004d0080: pop esi
         // 004d0081: call esi
         // 004d0083: add esp, 0x50
      [-]8bff558bec83ec
         // 004d0118: mov edi, edi
         // 004d011a: push ebp
         // 004d011b: mov ebp, esp
         // 004d011d: sub esp, 0x34
      [-]8bff558bec83ec
         // 004d0248: mov edi, edi
         // 004d024a: push ebp
         // 004d024b: mov ebp, esp
         // 004d024d: sub esp, 0x2c
      [-]000083c4
         // 004d026f: add esp, 0x10
      [-]8bff558bec83ec3c
         // 004d0350: mov edi, edi
         // 004d0352: push ebp
         // 004d0353: mov ebp, esp
         // 004d0355: sub esp, 0x3c
      [-]000083c4
         // 004d037e: add esp, 0x10
      [-]83c43c5dc3
         // 004d038f: add esp, 0x3c
         // 004d0392: pop ebp
         // 004d0393: retn
      [-]8bff558bec83ec
         // 004d04a4: mov edi, edi
         // 004d04a6: push ebp
         // 004d04a7: mov ebp, esp
         // 004d04a9: sub esp, 0x5c
      [-]8bff558bec83ec
         // 004d04f4: mov edi, edi
         // 004d04f6: push ebp
         // 004d04f7: mov ebp, esp
         // 004d04f9: sub esp, 0x38
      [-]000083c4
         // 004d051e: add esp, 0x10
      [-]8bff558bec83ec
         // 004d0654: mov edi, edi
         // 004d0656: push ebp
         // 004d0657: mov ebp, esp
         // 004d0659: sub esp, 0x30
      [-]feffff83c4
         // 004d067b: add esp, 0x8
      [-]8bff558bec83ec
         // 004d0718: mov edi, edi
         // 004d071a: push ebp
         // 004d071b: mov ebp, esp
         // 004d071d: sub esp, 0x4c
      [-]8bff558bec83ec
         // 004d07bc: mov edi, edi
         // 004d07be: push ebp
         // 004d07bf: mov ebp, esp
         // 004d07c1: sub esp, 0x5c
      [-]ffff83c4
         // 004d07e3: add esp, 0x8
      [-]8bff558bec83ec58
         // 004d092c: mov edi, edi
         // 004d092e: push ebp
         // 004d092f: mov ebp, esp
         // 004d0931: sub esp, 0x48
         // 004d0934: lea ebx, ds:[eax+0xffffffffffffffa4]
      [-]ffff83c4
         // 004d094d: add esp, 0x10
      [-]8bff558bec83ec
         // 004d0a0c: mov edi, edi
         // 004d0a0e: push ebp
         // 004d0a0f: mov ebp, esp
         // 004d0a11: sub esp, 0x50
      [-]ffff83c4
         // 004d0a2f: add esp, 0xc

  }
  condition:
    all of them
}

rule R2Sign_kryptik_VxSig {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         c745fc????????
         // 0041a984: mov ss:[ebp+0xfffffffffffffffc], 0x40
      [-]6a006affff15
         // 0041a997: push 0x0
         // 0041a999: push 0xffffffffffffffff
         // 0041a99b: call ds:[__imp_VirtualAllocEx]
      [-]41008be55dc3
         // 0041a9a1: mov esp, ebp
         // 0041a9a3: pop ebp
         // 0041a9a4: retn
      [-]558bec83ec
         // 0041a9c0: push ebp
         // 0041a9c1: mov ebp, esp
         // 0041a9c3: sub esp, 0x8
      [-]8b45088945
         // 0041a9c6: mov eax, ss:[ebp+0x8]
         // 0041a9c9: mov ss:[ebp+0xfffffffffffffffc], eax
      [-]8b4d0c894d
         // 0041a9cc: mov ecx, ss:[ebp+0xc]
         // 0041a9cf: mov ss:[ebp+0xfffffffffffffff8], ecx
      [-]8be55dc3
         // 0041a9e4: mov esp, ebp
         // 0041a9e6: pop ebp
         // 0041a9e7: retn
      [-]558bec8b45088b40fc5dc3
         // 0041aa10: push ebp
         // 0041aa11: mov ebp, esp
         // 0041aa13: mov eax, ss:[ebp+0x8]
         // 0041aa16: mov eax, ds:[eax+0xfffffffffffffffc]
         // 0041aa19: pop ebp
         // 0041aa1a: retn
      [-]558bec83ec
         // 0041abb0: push ebp
         // 0041abb1: mov ebp, esp
         // 0041abb3: sub esp, 0x14
      [-]518b55f452e8
         // 0041abec: push ecx
         // 0041abed: mov edx, ss:[ebp+0xfffffffffffffff4]
         // 0041abf0: push edx
         // 0041abf1: call 0x41aa30
      [-]8b45088b4d08034804894d08eb
         // 0041abf9: mov eax, ss:[ebp+0x8]
         // 0041abfc: mov ecx, ss:[ebp+0x8]
         // 0041abff: add ecx, ds:[eax+0x4]
         // 0041ac02: mov ss:[ebp+0x8], ecx
         // 0041ac05: jmp 0x41abb6
      [-]8be55dc3
         // 0041ac07: mov esp, ebp
         // 0041ac09: pop ebp
         // 0041ac0a: retn
      [-]558bec83ec
         // 0041ac10: push ebp
         // 0041ac11: mov ebp, esp
         // 0041ac13: sub esp, 0x10
      [-]ffff83c40889
         // 0041ada6: add esp, 0x8
         // 0041ada9: mov ss:[ebp+0xffffffffffffffb4], eax
      [-]83c40c8b55e40355
         // 0041adc5: add esp, 0xc
         // 0041adc8: mov edx, ss:[ebp+0xffffffffffffffe4]
         // 0041adcb: add edx, ss:[ebp+0xffffffffffffffcc]
      [-]ffff83c408c745
         // 0041adf5: add esp, 0x8
         // 0041adf8: mov ss:[ebp+0xffffffffffffffdc], 0x0
      [-]ffff8b0d
         // 0041ae0b: mov ecx, ds:[0x41da30]
      [-]ffff83c40489
         // 0041ae17: add esp, 0x4
         // 0041ae1a: mov ss:[ebp+0xffffffffffffff9c], eax
      [-]ffff83c4048945
         // 0041ae26: add esp, 0x4
         // 0041ae29: mov ss:[ebp+0xffffffffffffffe0], eax
      [-]506a008b4d
         // 0041ae2f: push eax
         // 0041ae30: push 0x0
         // 0041ae32: mov ecx, ss:[ebp+0xffffffffffffffe0]
      [-]ffff83c40c8b
         // 0041ae3b: add esp, 0xc
         // 0041ae3e: mov edx, ss:[ebp+0xffffffffffffff9c]
      [-]ffff83c40889
         // 0041ae59: add esp, 0x8
         // 0041ae5c: mov ss:[ebp+0xffffffffffffff90], eax
      [-]83c40c8b45e40345
         // 0041ae79: add esp, 0xc
         // 0041ae7c: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 0041ae7f: add eax, ss:[ebp+0xffffffffffffffcc]

  }
  condition:
    all of them
}

rule R2Sign_mediyes_VxSig {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         83c0ff894704
         // 100015af: add eax, 0xffffffffffffffff
         // 100015b2: mov ds:[edi+0x4], eax
      [-]385d0c740d
         // 100054a6: cmp b1 ss:[ebp+0xc], b1 bl
         // 100054a9: jz 0x100054b8
      [-]f74608????????0f85b2010000
         // 10012671: test ds:[esi+0x8], 0x800000
         // 10012678: jnz 0x10012830
      [-]8b442438c6030166c743021000814d04????????25????????3d????????773f
         // 10013ee0: mov eax, ss:[esp+0x38]
         // 10013ee4: mov b1 ds:[ebx], b1 0x1
         // 10013ee7: mov b2 ds:[ebx+0x2], b2 0x10
         // 10013eed: or ss:[ebp+0x4], 0x2000
         // 10013ef4: and eax, 0x1f80
         // 10013ef9: cmp eax, 0x400
         // 10013efe: ja 0x10013f3f
      [-]80fa677547
         // 1001f133: cmp b1 dl, b1 0x67
         // 1001f136: jnz 0x1001f17f
      [-]5353535353e8c25cffff83c4148bc6eb3d
         // 10020453: push ebx
         // 10020454: push ebx
         // 10020455: push ebx
         // 10020456: push ebx
         // 10020457: push ebx
         // 10020458: call 0x1001611f
         // 1002045d: add esp, 0x14
         // 10020460: mov eax, esi
         // 10020462: jmp 0x100204a1
      [-]8b450c6a50885c06ff58e978ffffff
         // 1002058a: mov eax, ss:[ebp+0xc]
         // 1002058d: push 0x50
         // 1002058f: mov b1 ds:[esi+eax+0xffffffffffffffff], b1 bl
         // 10020593: pop eax
         // 10020594: jmp 0x10020511
      [-]8b442404a3????????c3
         // 10020e80: mov eax, ss:[esp+0x4]
         // 10020e84: mov ds:[0x10066c80], eax
         // 10020e89: retn
      [-]83f8647217
         // 10022f05: cmp eax, 0x64
         // 10022f08: jb 0x10022f21
      [-]b8????????f7e1c1ea0f69d2????????03cab8????????f7e7c1ea0f69d2????????03fa
         // 10027b73: mov eax, 0xffffffff80078071
         // 10027b78: mul ecx
         // 10027b7a: shr edx, b1 0xf
         // 10027b7d: imul edx, 0xffffffffffff000f
         // 10027b83: add ecx, edx
         // 10027b85: mov eax, 0xffffffff80078071
         // 10027b8a: mul edi
         // 10027b8c: shr edx, b1 0xf
         // 10027b8f: imul edx, 0xffffffffffff000f
         // 10027b95: add edi, edx
      [-]8d4dc4e9288cfdff
         // 1002a6f0: lea ecx, ss:[ebp+0xffffffffffffffc4]
         // 1002a6f3: jmp 0x10003320

  }
  condition:
    all of them
}

rule R2Sign_sirefef_VxSig {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         558bec51
         // 004223b0: push ebp
         // 004223b1: mov ebp, esp
         // 004223b3: push ecx
      [-]c9c20400
         // 0042240b: leave
         // 0042240c: retn b2 0x4

  }
  condition:
    all of them
}

rule R2Sign_upatre_VxSig {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         558bec83ec108b450825????????b9????????eb05
         // 0040133b: push ebp
         // 0040133c: mov ebp, esp
         // 0040133e: sub esp, 0x10
         // 00401341: mov eax, ss:[ebp+0x8]
         // 00401344: and eax, 0xffffffffffff0000
         // 00401349: mov ecx, 0x5a4d
         // 0040134e: jmp 0x401355
      [-]0fb7483c538945fc8d440118b9????????56576639080f8598000000
         // 0040135a: movzx ecx, b2 ds:[eax+0x3c]
         // 0040135e: push ebx
         // 0040135f: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00401362: lea eax, ds:[ecx+eax+0x18]
         // 00401366: mov ecx, 0x10b
         // 0040136b: push esi
         // 0040136c: push edi
         // 0040136d: cmp b2 ds:[eax], b2 cx
         // 00401370: jnz 0x40140e
      [-]8b70600375fc8b7e208b4614037dfc8945f48b5d0c4b33c033c9fec8
         // 00401376: mov esi, ds:[eax+0x60]
         // 00401379: add esi, ss:[ebp+0xfffffffffffffffc]
         // 0040137c: mov edi, ds:[esi+0x20]
         // 0040137f: mov eax, ds:[esi+0x14]
         // 00401382: add edi, ss:[ebp+0xfffffffffffffffc]
         // 00401385: mov ss:[ebp+0xfffffffffffffff4], eax
         // 00401388: mov ebx, ss:[ebp+0xc]
         // 0040138b: dec ebx
         // 0040138c: xor eax, eax
         // 0040138e: xor ecx, ecx
         // 00401390: dec b1 al
      [-]8b070345fc8bd84b33c0fec8
         // 004013a6: mov eax, ds:[edi]
         // 004013a8: add eax, ss:[ebp+0xfffffffffffffffc]
         // 004013ab: mov ebx, eax
         // 004013ad: dec ebx
         // 004013ae: xor eax, eax
         // 004013b0: dec b1 al
      [-]fec0438a0b80f90075f6
         // 004013b2: inc b1 al
         // 004013b4: inc ebx
         // 004013b5: mov b1 cl, b1 ds:[ebx]
         // 004013b7: cmp b1 cl, b1 0x0
         // 004013ba: jnz 0x4013b2
      [-]83c704ff45f88b45f83b45f472c5
         // 004013d3: add edi, 0x4
         // 004013d6: inc ss:[ebp+0xfffffffffffffff8]
         // 004013d9: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 004013dc: cmp eax, ss:[ebp+0xfffffffffffffff4]
         // 004013df: jb 0x4013a6
      [-]8b45f83b45f47325
         // 004013e1: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 004013e4: cmp eax, ss:[ebp+0xfffffffffffffff4]
         // 004013e7: jnb 0x40140e
      [-]8b4e10492bc18b4e2403c803c88b45fc03c80fb7018b4e1c8d04818b4dfc8b040103c1eb02
         // 004013e9: mov ecx, ds:[esi+0x10]
         // 004013ec: dec ecx
         // 004013ed: sub eax, ecx
         // 004013ef: mov ecx, ds:[esi+0x24]
         // 004013f2: add ecx, eax
         // 004013f4: add ecx, eax
         // 004013f6: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 004013f9: add ecx, eax
         // 004013fb: movzx eax, b2 ds:[ecx]
         // 004013fe: mov ecx, ds:[esi+0x1c]
         // 00401401: lea eax, ds:[ecx+eax*0x4]
         // 00401404: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00401407: mov eax, ds:[ecx+eax]
         // 0040140a: add eax, ecx
         // 0040140c: jmp 0x401410
      [-]5f5e5b8be55dc20800
         // 00401410: pop edi
         // 00401411: pop esi
         // 00401412: pop ebx
         // 00401413: mov esp, ebp
         // 00401415: pop ebp
         // 00401416: retn b2 0x8
      [-]eb0003f88d0d
         // 00402bdb: jmp 0x402bdd
         // 00402bdd: add edi, eax
         // 00402bdf: lea ecx, ds:[0x4040f2]
      [-]8b0aeb05
         // 00402cd8: mov ecx, ds:[edx]
         // 00402cda: jmp 0x402ce1
      [-]474975e4
         // 00402d1f: inc edi
         // 00402d20: dec ecx
         // 00402d21: jnz 0x402d07
      [-]3bc17308
         // 00402dc2: cmp eax, ecx
         // 00402dc4: jnb 0x402dce
      [-]fec03c00750e
         // 00402e04: inc b1 al
         // 00402e06: cmp b1 al, b1 0x0
         // 00402e08: jnz 0x402e18
      [-]0fb7024242eb09
         // 00402e11: movzx eax, b2 ds:[edx]
         // 00402e14: inc edx
         // 00402e15: inc edx
         // 00402e16: jmp 0x402e21
      [-]8a068a0f3bc17508
         // 00402f75: mov b1 al, b1 ds:[esi]
         // 00402f77: mov b1 cl, b1 ds:[edi]
         // 00402f79: cmp eax, ecx
         // 00402f7b: jnz 0x402f85
      [-]6a00ff15
         // 0040318d: push 0x0
         // 0040318f: call ds:[CreateWindowExA]
      [-]6a1c6a0068????????ff7508ff15
         // 004031ac: push 0x1c
         // 004031ae: push 0x0
         // 004031b0: push 0x111
         // 004031b5: push ss:[ebp+0x8]
         // 004031b8: call ds:[SendMessageA]
      [-]4040006a00ff35
         // 004031be: push 0x0
         // 004031c0: push ds:[0x4040f2]
      [-]ff1508404000a3
         // 004031f0: call ds:[GetLastError]
         // 004031f6: mov ds:[0x40413a], eax
      [-]6a02ff750c6a2268????????68????????6a0a68????????68
         // 00403208: push 0x2
         // 0040320a: push ss:[ebp+0xc]
         // 0040320d: push 0x22
         // 0040320f: push 0xa6
         // 00403214: push 0x17c
         // 00403219: push 0xa
         // 0040321b: push 0x40000001
         // 00403220: push 0x404559
      [-]8b3a4242eb03
         // 004032d8: mov edi, ds:[edx]
         // 004032da: inc edx
         // 004032db: inc edx
         // 004032dc: jmp 0x4032e1
      [-]83f805753e
         // 00403363: cmp eax, 0x5
         // 00403366: jnz 0x4033a6
      [-]8d45f050ff7508ff15
         // 00403368: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 0040336b: push eax
         // 0040336c: push ss:[ebp+0x8]
         // 0040336f: call ds:[GetWindowRect]
      [-]83fb1c753d
         // 004034b8: cmp ebx, 0x1c
         // 004034bb: jnz 0x4034fa
      [-]6a1b6a0068????????ff7508ff15
         // 004034c2: push 0x1b
         // 004034c4: push 0x0
         // 004034c6: push 0x111
         // 004034cb: push ss:[ebp+0x8]
         // 004034ce: call ds:[SendMessageA]
      [-]41418bd941
         // 00403510: inc ecx
         // 00403511: inc ecx
         // 00403512: mov ebx, ecx
         // 00403514: inc ecx
      [-]890203d34975e8
         // 00403526: mov ds:[edx], eax
         // 00403528: add edx, ebx
         // 0040352a: dec ecx
         // 0040352b: jnz 0x403515
      [-]58c1e0080105
         // 00403569: pop eax
         // 0040356a: shl eax, b1 0x8
         // 0040356d: add ds:[0x4046a0], eax
      [-]404000e903
         // 004035d4: jmp 0x4038f2
      [-]8b5510eb03
         // 004035e4: mov edx, ss:[ebp+0x10]
         // 004035e7: jmp 0x4035ec
      [-]4000eb03
         // 00403603: jmp 0x403608
      [-]598bc183e1075f85c97417
         // 00403646: pop ecx
         // 00403647: mov eax, ecx
         // 00403649: and ecx, 0x7
         // 0040364c: pop edi
         // 0040364d: test ecx, ecx
         // 0040364f: jz 0x403668
      [-]83c2054a5256eb03
         // 0040369d: add edx, 0x5
         // 004036a0: dec edx
         // 004036a1: push edx
         // 004036a2: push esi
         // 004036a3: jmp 0x4036a8
      [-]23de68????????53a1
         // 004036fd: and ebx, esi
         // 004036ff: push 0x2000
         // 00403704: push ebx
         // 00403705: mov eax, ds:[0x404142]
      [-]bf????????eb03
         // 00403758: mov edi, 0xfff
         // 0040375d: jmp 0x403762
      [-]6a226a0068????????ff7508ff15
         // 00403795: push 0x22
         // 00403797: push 0x0
         // 00403799: push 0x111
         // 0040379e: push ss:[ebp+0x8]
         // 004037a1: call ds:[SendMessageA]
      [-]83fb1e7550
         // 0040384b: cmp ebx, 0x1e
         // 0040384e: jnz 0x4038a0
      [-]8b070302eb03
         // 00403878: mov eax, ds:[edi]
         // 0040387a: add eax, ds:[edx]
         // 0040387c: jmp 0x403881
      [-]8be55dc21000
         // 004038f4: mov esp, ebp
         // 004038f6: pop ebp
         // 004038f7: retn b2 0x10

  }
  condition:
    all of them
}

rule R2Sign_zbot_VxSig {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         558bec8b45088b40fc5dc3
         // 00401000: push ebp
         // 00401001: mov ebp, esp
         // 00401003: mov eax, ss:[ebp+0x8]
         // 00401006: mov eax, ds:[eax+0xfffffffffffffffc]
         // 00401009: pop ebp
         // 0040100a: retn
      [-]558bec83ec14
         // 00401010: push ebp
         // 00401011: mov ebp, esp
         // 00401013: sub esp, 0x14
      [-]8b4508837804000f84
         // 00401016: mov eax, ss:[ebp+0x8]
         // 00401019: cmp ds:[eax+0x4], 0x0
         // 0040101d: jz 0x4010b7
      [-]8b4d088b510483ea08d1ea8955f48b450883c0088945f0c745fc????????eb09
         // 0040102a: mov ecx, ss:[ebp+0x8]
         // 0040102d: mov edx, ds:[ecx+0x4]
         // 00401030: sub edx, 0x8
         // 00401033: shr edx, b1 0x1
         // 00401035: mov ss:[ebp+0xfffffffffffffff4], edx
         // 00401038: mov eax, ss:[ebp+0x8]
         // 0040103b: add eax, 0x8
         // 0040103e: mov ss:[ebp+0xfffffffffffffff0], eax
         // 00401041: mov ss:[ebp+0xfffffffffffffffc], 0x0
         // 00401048: jmp 0x401053
      [-]8b55fc3b55f473
         // 00401053: mov edx, ss:[ebp+0xfffffffffffffffc]
         // 00401056: cmp edx, ss:[ebp+0xfffffffffffffff4]
         // 00401059: jnb 0x4010a6
      [-]8b45fc8b4df00fb71441c1fa0c83fa0375
         // 0040105b: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 0040105e: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 00401061: movzx edx, b2 ds:[ecx+eax*0x2]
         // 00401065: sar edx, b1 0xc
         // 00401068: cmp edx, 0x3
         // 0040106b: jnz 0x4010a4
      [-]8955f88b45088b4d0c03088b55f88b
         // 00401080: mov ss:[ebp+0xfffffffffffffff8], edx
         // 00401083: mov eax, ss:[ebp+0x8]
         // 00401086: mov ecx, ss:[ebp+0xc]
         // 00401089: add ecx, ds:[eax]
         // 0040108b: mov edx, ss:[ebp+0xfffffffffffffff8]
         // 0040108e: mov eax, ds:[ecx+edx+0xffffffffffffffc8]
      [-]0345108b4d088b550c03118b4df889
         // 00401092: add eax, ss:[ebp+0x10]
         // 00401095: mov ecx, ss:[ebp+0x8]
         // 00401098: mov edx, ss:[ebp+0xc]
         // 0040109b: add edx, ds:[ecx]
         // 0040109d: mov ecx, ss:[ebp+0xfffffffffffffff8]
         // 004010a0: mov ds:[edx+ecx+0xffffffffffffffc8], eax
      [-]8b55088b4508034204894508e9
         // 004010a6: mov edx, ss:[ebp+0x8]
         // 004010a9: mov eax, ss:[ebp+0x8]
         // 004010ac: add eax, ds:[edx+0x4]
         // 004010af: mov ss:[ebp+0x8], eax
         // 004010b2: jmp 0x401016
      [-]8be55dc3
         // 004010b7: mov esp, ebp
         // 004010b9: pop ebp
         // 004010ba: retn
      [-]c745fc????????68
         // 004011f4: mov ss:[ebp+0xfffffffffffffffc], 0x4
         // 004011fd: push 0x3000
      [-]506a00ff
         // 00401205: push eax
         // 00401206: push 0x0
         // 0040120a: call ds:[__imp_VirtualAllocEx]
      [-]8be55dc3
         // 00401210: mov esp, ebp
         // 00401212: pop ebp
         // 00401213: retn
      [-]558bec83ec088b45088945fc8b4d0c894df88b55fc3b55f87307
         // 00401220: push ebp
         // 00401221: mov ebp, esp
         // 00401223: sub esp, 0x8
         // 00401226: mov eax, ss:[ebp+0x8]
         // 00401229: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0040122c: mov ecx, ss:[ebp+0xc]
         // 0040122f: mov ss:[ebp+0xfffffffffffffff8], ecx
         // 00401232: mov edx, ss:[ebp+0xfffffffffffffffc]
         // 00401235: cmp edx, ss:[ebp+0xfffffffffffffff8]
         // 00401238: jnb 0x401241
      [-]8b45fceb05
         // 0040123a: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 0040123d: jmp 0x401244
      [-]8be55dc3
         // 00401244: mov esp, ebp
         // 00401246: pop ebp
         // 00401247: retn
      [-]558bec83ec
         // 00401250: push ebp
         // 00401251: mov ebp, esp
         // 00401253: sub esp, 0x14
      [-]c745f4????????eb09
         // 0040125d: mov ss:[ebp+0xfffffffffffffff4], 0x0
         // 00401264: jmp 0x40126f
      [-]8b4df43b4d0c73
         // 0040126f: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 00401272: cmp ecx, ss:[ebp+0xc]
         // 00401275: jnb 0x4012d2
      [-]558bec81ec
         // 00401340: push ebp
         // 00401341: mov ebp, esp
         // 00401343: sub esp, 0x178
      [-]68????????6a0068
         // 00401392: push 0x20019
         // 00401397: push 0x0
         // 00401399: push 0x445080
      [-]6a04ff15
         // 004013af: push 0x4
         // 004013b1: call ds:[__imp_LoadLibraryW]
      [-]0033c0e9
         // 004013b7: xor eax, eax
         // 004013b9: jmp 0x401812
      [-]52ff95????????
         // 004014b2: push edx
         // 004014b3: call ss:[ebp+0xfffffffffffffea4]
      [-]fcffff83c4088985
         // 004015d5: add esp, 0x8
         // 004015d8: mov ss:[ebp+0xfffffffffffffea8], eax
      [-]0395????????528b85
         // 004015eb: add edx, ss:[ebp+0xfffffffffffffedc]
         // 004015f1: push edx
         // 004015f2: mov eax, ss:[ebp+0xfffffffffffffebc]
      [-]83c40c8b8d????????038d
         // 00401604: add esp, 0xc
         // 00401607: mov ecx, ss:[ebp+0xfffffffffffffee4]
         // 0040160d: add ecx, ss:[ebp+0xfffffffffffffec0]
      [-]038d????????898d????????8b95
         // 00401613: add ecx, ss:[ebp+0xfffffffffffffedc]
         // 00401619: mov ss:[ebp+0xfffffffffffffedc], ecx
         // 0040161f: mov edx, ss:[ebp+0xfffffffffffffeb8]
      [-]e968ffffff
         // 00401643: jmp 0x4015b0
      [-]fbffff83c4088985
         // 004016ef: add esp, 0x8
         // 004016f2: mov ss:[ebp+0xfffffffffffffe88], eax
      [-]0385????????508b8d????????038d
         // 00401705: add eax, ss:[ebp+0xfffffffffffffedc]
         // 0040170b: push eax
         // 0040170c: mov ecx, ss:[ebp+0xfffffffffffffee0]
         // 00401712: add ecx, ss:[ebp+0xfffffffffffffe9c]
      [-]83c40c8b95????????0395
         // 0040171e: add esp, 0xc
         // 00401721: mov edx, ss:[ebp+0xfffffffffffffee4]
         // 00401727: add edx, ss:[ebp+0xfffffffffffffec0]
      [-]0395????????8995????????8b85
         // 0040172d: add edx, ss:[ebp+0xfffffffffffffedc]
         // 00401733: mov ss:[ebp+0xfffffffffffffedc], edx
         // 00401739: mov eax, ss:[ebp+0xfffffffffffffe9c]
      [-]528b85????????50e8
         // 00401768: push edx
         // 00401769: mov eax, ss:[ebp+0xfffffffffffffee0]
         // 0040176f: push eax
         // 00401770: call 0x401250
      [-]ffff83c4088b8d
         // 00401775: add esp, 0x8
         // 00401778: mov ecx, ss:[ebp+0xfffffffffffffebc]
      [-]68????????ff15
         // 004017a9: push 0xffffffff80000002
         // 004017ae: call ds:[__imp_RegOpenKeyExW]
      [-]0085c07404
         // 004017b4: test eax, eax
         // 004017b6: jz 0x4017bc
      [-]518b55fc81c2????????52e8
         // 004017c7: push ecx
         // 004017c8: mov edx, ss:[ebp+0xfffffffffffffffc]
         // 004017cb: add edx, 0x300
         // 004017d1: push edx
         // 004017d2: call 0x4012e0
      [-]83c40c8b45fc2d????????508b4dfc518b95????????52e8
         // 004017d7: add esp, 0xc
         // 004017da: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 004017dd: sub eax, 0x400000
         // 004017e2: push eax
         // 004017e3: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 004017e6: push ecx
         // 004017e7: mov edx, ss:[ebp+0xfffffffffffffee0]
         // 004017ed: push edx
         // 004017ee: call 0x401010
      [-]ffff83c40c8b25
         // 004017f3: add esp, 0xc
         // 004017f6: mov esp, ds:[0x446fac]

  }
  condition:
    all of them
}
