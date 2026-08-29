/*
   YARA Rule Set
   Author: yarGen
   Date: 2026-08-29
   Identifier: mediyes
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_11040aa18c7311b97c83b56652770374154d3277a6163c4fb0460aede20b09f9 {
   meta:
      description = "mediyes - file 11040aa18c7311b97c83b56652770374154d3277a6163c4fb0460aede20b09f9.exe"
      author = "yarGen"
      date = "2026-08-29"
      hash1 = "11040aa18c7311b97c83b56652770374154d3277a6163c4fb0460aede20b09f9"
      score = 75
   strings:
      $s1 = "KERNEL32.DLL" fullword ascii /* goodware: 1 */
      $s2 = "kernel32.dll" fullword ascii /* goodware: 1 */
      $s3 = "ADVAPI32.dll" fullword ascii /* goodware: 1 */
      $s4 = "mscoree.dll" fullword ascii /* goodware: 1 */
      $s5 = "ole32.dll" fullword ascii /* goodware: 1 */
      $s6 = "svchost.exe" fullword wide
      $s7 = "OLEAUT32.dll" fullword ascii /* goodware: 1 */
      $s8 = "USER32.DLL" fullword ascii
      $s9 = "USER32.dll" fullword ascii
      $s10 = "GetProcessWindowStation" fullword ascii /* goodware: 1 */
      $s11 = "GetProcessHeap" fullword ascii /* goodware: 1 */
      $s12 = "RPCRT4.dll" fullword ascii
      $s13 = "wkssvc.dll" fullword wide
      $s14 = "KERNEL32.dll" fullword ascii /* goodware: 5 */
      $s15 = "wssl.dll" fullword wide
      $s16 = "GetCurrentProcess" fullword ascii /* goodware: 3 */
      $s17 = "GetCurrentProcessId" fullword ascii /* goodware: 3 */
      $s18 = "r\\ntdll.dll" fullword wide
      $s19 = "WS2_32.dll" fullword ascii
      $s20 = "ReleaseMutex" fullword ascii /* goodware: 1 */
   condition:
      8 of ($s*)
}

rule sig_8ad64f391dc4018f647c775cfa99116d6bc40e0afd2b7c5b2f87c8abe06812ca {
   meta:
      description = "mediyes - file 8ad64f391dc4018f647c775cfa99116d6bc40e0afd2b7c5b2f87c8abe06812ca.exe"
      author = "yarGen"
      date = "2026-08-29"
      hash1 = "8ad64f391dc4018f647c775cfa99116d6bc40e0afd2b7c5b2f87c8abe06812ca"
      score = 75
   strings:
      $x1 = "c:\\totalcmd\\dllexec.exe" fullword ascii
      $s2 = "kernel32.dll" fullword ascii /* goodware: 1 */
      $s3 = "KERNEL32.DLL" fullword ascii /* goodware: 1 */
      $s4 = "mscoree.dll" fullword ascii /* goodware: 1 */
      $s5 = "ADVAPI32.dll" fullword ascii /* goodware: 1 */
      $s6 = "OLEAUT32.dll" fullword ascii /* goodware: 1 */
      $s7 = "ole32.dll" fullword ascii /* goodware: 1 */
      $s8 = "svchost.exe" fullword wide
      $s9 = "USER32.dll" fullword ascii
      $s10 = "USER32.DLL" fullword ascii
      $s11 = "GetProcessHeap" fullword ascii /* goodware: 1 */
      $s12 = "GetProcessWindowStation" fullword ascii /* goodware: 1 */
      $s13 = "wkssvc.dll" fullword wide
      $s14 = "RPCRT4.dll" fullword ascii
      $s15 = "KERNEL32.dll" fullword ascii /* goodware: 5 */
      $s16 = "wssl.dll" fullword wide
      $s17 = "GetCurrentProcess" fullword ascii /* goodware: 3 */
      $s18 = "GetCurrentProcessId" fullword ascii /* goodware: 3 */
      $s19 = "r\\ntdll.dll" fullword wide
      $s20 = "WS2_32.dll" fullword ascii
   condition:
      1 of ($x*) and 4 of ($s*)
}

rule a616f9ac37c0a1ed6f291cab72457c887f1713a41a2ed171836564a3b6de74a7 {
   meta:
      description = "mediyes - file a616f9ac37c0a1ed6f291cab72457c887f1713a41a2ed171836564a3b6de74a7.exe"
      author = "yarGen"
      date = "2026-08-29"
      hash1 = "a616f9ac37c0a1ed6f291cab72457c887f1713a41a2ed171836564a3b6de74a7"
      score = 75
   strings:
      $s1 = "svchost.exe" fullword wide
      $s2 = "kernel32.dll" fullword ascii /* goodware: 1 */
      $s3 = "ADVAPI32.dll" fullword ascii /* goodware: 1 */
      $s4 = "KERNEL32.DLL" fullword ascii /* goodware: 1 */
      $s5 = "OLEAUT32.dll" fullword ascii /* goodware: 1 */
      $s6 = "mscoree.dll" fullword ascii /* goodware: 1 */
      $s7 = "ole32.dll" fullword ascii /* goodware: 1 */
      $s8 = "USER32.dll" fullword ascii
      $s9 = "USER32.DLL" fullword ascii
      $s10 = "GetProcessHeap" fullword ascii /* goodware: 1 */
      $s11 = "GetProcessWindowStation" fullword ascii /* goodware: 1 */
      $s12 = "wssl.dll" fullword wide
      $s13 = "RPCRT4.dll" fullword ascii
      $s14 = "wkssvc.dll" fullword wide
      $s15 = "KERNEL32.dll" fullword ascii /* goodware: 5 */
      $s16 = "GetCurrentProcess" fullword ascii /* goodware: 3 */
      $s17 = "GetCurrentProcessId" fullword ascii /* goodware: 3 */
      $s18 = "C:\\WINDOWS\\explorer.exe" fullword ascii
      $s19 = "r\\ntdll.dll" fullword wide
      $s20 = "WS2_32.dll" fullword ascii
   condition:
      8 of ($s*)
}

