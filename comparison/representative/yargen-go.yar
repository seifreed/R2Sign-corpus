/*
   YARA Rule Set
   Author: yarGen-Go
   Date: 2026-09-04
   Identifier: cabby
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_0cb17078bb20234b689836ff48c147ebcdf4abc3fe82e42ba51454fe1cb4a1e5 {
   meta:
      description = "cabby - file 0cb17078bb20234b689836ff48c147ebcdf4abc3fe82e42ba51454fe1cb4a1e5.exe"
      author = "yarGen-Go"
      date = "2026-09-04"
      hash1 = "0cb17078bb20234b689836ff48c147ebcdf4abc3fe82e42ba51454fe1cb4a1e5"
      score = 75
   strings:
      $s1 = "kernel32.DLL" fullword ascii
      $s2 = "modemui.dll" fullword ascii
      $s3 = "certcli.dll" fullword ascii
      $s4 = "msimg32.dll" fullword ascii /* goodware: 6 */
      $s5 = "WTSAPI32.dll" fullword ascii /* goodware: 8 */
      $s6 = "WTSEnumerateProcessesA" fullword ascii /* goodware: 1 */
      $s7 = "GetPrivateProfileSectionA" fullword ascii /* goodware: 1 */
      $s8 = "proftur.pdb" fullword ascii
      $s9 = "CreateNamedPipeA" fullword ascii /* goodware: 4 */
      $s10 = "GetAtomNameA" fullword ascii /* goodware: 1 */
      $s11 = "GetConsoleTitleA" fullword ascii /* goodware: 2 */
      $s12 = "GetBinaryTypeA" fullword ascii
      $s13 = "WTSQueryUserToken" fullword ascii /* goodware: 1 */
      $s14 = "CreateServiceA" fullword ascii /* goodware: 2 */
      $s15 = "WTSSetUserConfigW" fullword ascii
      $s16 = "WTSEnumerateSessionsW" fullword ascii /* goodware: 2 */
      $s17 = "GetPrivateProfileIntA" fullword ascii /* goodware: 8 */
      $s18 = "GetLongPathNameA" fullword ascii /* goodware: 6 */
      $s19 = "InvokeControlPanel" fullword ascii
      $s20 = "GetProcessId" fullword ascii /* goodware: 17 */
   condition:
      8 of ($s*)
}

rule sig_13ab0448483994b2a8e737655a844246f5974e46f2bba4e1164518610300e573 {
   meta:
      description = "cabby - file 13ab0448483994b2a8e737655a844246f5974e46f2bba4e1164518610300e573.exe"
      author = "yarGen-Go"
      date = "2026-09-04"
      hash1 = "13ab0448483994b2a8e737655a844246f5974e46f2bba4e1164518610300e573"
      score = 75
   strings:
      $s1 = "kernel32.DLL" fullword ascii
      $s2 = "modemui.dll" fullword ascii
      $s3 = "certcli.dll" fullword ascii
      $s4 = "msimg32.dll" fullword ascii /* goodware: 6 */
      $s5 = "WTSAPI32.dll" fullword ascii /* goodware: 8 */
      $s6 = "WTSEnumerateProcessesA" fullword ascii /* goodware: 1 */
      $s7 = "GetPrivateProfileSectionA" fullword ascii /* goodware: 1 */
      $s8 = "proftur.pdb" fullword ascii
      $s9 = "CreateNamedPipeA" fullword ascii /* goodware: 4 */
      $s10 = "GetAtomNameA" fullword ascii /* goodware: 1 */
      $s11 = "GetConsoleTitleA" fullword ascii /* goodware: 2 */
      $s12 = "GetBinaryTypeA" fullword ascii
      $s13 = "WTSQueryUserToken" fullword ascii /* goodware: 1 */
      $s14 = "CreateServiceA" fullword ascii /* goodware: 2 */
      $s15 = "WTSSetUserConfigW" fullword ascii
      $s16 = "WTSEnumerateSessionsW" fullword ascii /* goodware: 2 */
      $s17 = "GetPrivateProfileIntA" fullword ascii /* goodware: 8 */
      $s18 = "GetLongPathNameA" fullword ascii /* goodware: 6 */
      $s19 = "InvokeControlPanel" fullword ascii
      $s20 = "GetProcessId" fullword ascii /* goodware: 17 */
   condition:
      8 of ($s*)
}

rule sig_176f3ad6537a7c5f84d038bb961b14f28eba7ed32883bff4cca87581b978b657 {
   meta:
      description = "cabby - file 176f3ad6537a7c5f84d038bb961b14f28eba7ed32883bff4cca87581b978b657.exe"
      author = "yarGen-Go"
      date = "2026-09-04"
      hash1 = "176f3ad6537a7c5f84d038bb961b14f28eba7ed32883bff4cca87581b978b657"
      score = 75
   strings:
      $s1 = "kernel32.DLL" fullword ascii
      $s2 = "modemui.dll" fullword ascii
      $s3 = "certcli.dll" fullword ascii
      $s4 = "msimg32.dll" fullword ascii /* goodware: 6 */
      $s5 = "WTSAPI32.dll" fullword ascii /* goodware: 8 */
      $s6 = "WTSEnumerateProcessesA" fullword ascii /* goodware: 1 */
      $s7 = "GetPrivateProfileSectionA" fullword ascii /* goodware: 1 */
      $s8 = "proftur.pdb" fullword ascii
      $s9 = "CreateNamedPipeA" fullword ascii /* goodware: 4 */
      $s10 = "GetAtomNameA" fullword ascii /* goodware: 1 */
      $s11 = "GetConsoleTitleA" fullword ascii /* goodware: 2 */
      $s12 = "GetBinaryTypeA" fullword ascii
      $s13 = "WTSQueryUserToken" fullword ascii /* goodware: 1 */
      $s14 = "CreateServiceA" fullword ascii /* goodware: 2 */
      $s15 = "WTSSetUserConfigW" fullword ascii
      $s16 = "WTSEnumerateSessionsW" fullword ascii /* goodware: 2 */
      $s17 = "GetPrivateProfileIntA" fullword ascii /* goodware: 8 */
      $s18 = "GetLongPathNameA" fullword ascii /* goodware: 6 */
      $s19 = "InvokeControlPanel" fullword ascii
      $s20 = "GetProcessId" fullword ascii /* goodware: 17 */
   condition:
      8 of ($s*)
}

/* Super Rules ------------------------------------------------------------- */

rule sig_0cb17078bb20234b689836ff48c147ebcdf4abc3fe82e42ba51454fe1cb4a1e5_13ab0448483994b2a8e737655a844246f59_super {
   meta:
      description = "cabby - from files 0cb17078bb20234b689836ff48c147ebcdf4abc3fe82e42ba51454fe1cb4a1e5.exe, 13ab0448483994b2a8e737655a844246f5974e46f2bba4e1164518610300e573.exe, 176f3ad6537a7c5f84d038bb961b14f28eba7ed32883bff4cca87581b978b657.exe"
      author = "yarGen-Go"
      date = "2026-09-04"
      hash1 = "0cb17078bb20234b689836ff48c147ebcdf4abc3fe82e42ba51454fe1cb4a1e5"
      hash2 = "13ab0448483994b2a8e737655a844246f5974e46f2bba4e1164518610300e573"
      hash3 = "176f3ad6537a7c5f84d038bb961b14f28eba7ed32883bff4cca87581b978b657"
      score = 75
   strings:
      $s1 = "modemui.dll" fullword ascii
      $s2 = "certcli.dll" fullword ascii
      $s3 = "kernel32.DLL" fullword ascii
      $s4 = "msimg32.dll" fullword ascii /* goodware: 6 */
      $s5 = "WTSAPI32.dll" fullword ascii /* goodware: 8 */
      $s6 = "WTSEnumerateProcessesA" fullword ascii /* goodware: 1 */
      $s7 = "GetPrivateProfileSectionA" fullword ascii /* goodware: 1 */
      $s8 = "proftur.pdb" fullword ascii
      $s9 = "CreateNamedPipeA" fullword ascii /* goodware: 4 */
      $s10 = "GetAtomNameA" fullword ascii /* goodware: 1 */
      $s11 = "GetConsoleTitleA" fullword ascii /* goodware: 2 */
      $s12 = "GetBinaryTypeA" fullword ascii
      $s13 = "WTSQueryUserToken" fullword ascii /* goodware: 1 */
      $s14 = "CreateServiceA" fullword ascii /* goodware: 2 */
      $s15 = "WTSEnumerateSessionsW" fullword ascii /* goodware: 2 */
      $s16 = "WTSSetUserConfigW" fullword ascii
      $s17 = "GetPrivateProfileIntA" fullword ascii /* goodware: 8 */
      $s18 = "InvokeControlPanel" fullword ascii
      $s19 = "GetProcessId" fullword ascii /* goodware: 17 */
      $s20 = "GetLongPathNameA" fullword ascii /* goodware: 6 */
   condition:
      (8 of ($s*))
      or (all of them)
}

/*
   YARA Rule Set
   Author: yarGen-Go
   Date: 2026-09-04
   Identifier: fakeav
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_1706022cd4215c5f54f3d203d432a70d881a1bf7636c41130fa88a7094c328ab {
   meta:
      description = "fakeav - file 1706022cd4215c5f54f3d203d432a70d881a1bf7636c41130fa88a7094c328ab.exe"
      author = "yarGen-Go"
      date = "2026-09-04"
      hash1 = "1706022cd4215c5f54f3d203d432a70d881a1bf7636c41130fa88a7094c328ab"
      score = 75
   strings:
      $s1 = "MSASN1.dll" fullword ascii
      $s2 = "DPNET.dll" fullword ascii
      $s3 = "xqpIPE3_[" fullword ascii
      $s4 = "o&O:\\6<W--" fullword ascii
      $s5 = "D\"y#%u;~" fullword ascii
      $s6 = "\\:Hzzw3E" fullword ascii
      $s7 = ">FX3#Z5o" fullword ascii
      $s8 = "lCUZ*X:+" fullword ascii
      $s9 = "PulseEvent" fullword ascii
      $s10 = "ASN1BERDecCheck" fullword ascii
      $s11 = "ASN1BERDecBool" fullword ascii
      $s12 = "ASN1BEREncBool" fullword ascii
      $s13 = "ASN1BEREncEoid" fullword ascii
      $s14 = "ASN1BERDecNull" fullword ascii
      $s15 = "DirectPlay8Create" fullword ascii
      $s16 = "ureg~dll" fullword ascii
      $s17 = "/\\n?k4\"`K" fullword ascii
      $s18 = "]o8-(S2}" fullword ascii
      $s19 = "L$/$g!I^" fullword ascii
      $s20 = "PJ|?v=+a" fullword ascii
   condition:
      8 of ($s*)
}

rule sig_1ad0e3f2fee448eb3efa7b0b4408b28b66418c373f30ffece5a58a734edfe5c5 {
   meta:
      description = "fakeav - file 1ad0e3f2fee448eb3efa7b0b4408b28b66418c373f30ffece5a58a734edfe5c5.exe"
      author = "yarGen-Go"
      date = "2026-09-04"
      hash1 = "1ad0e3f2fee448eb3efa7b0b4408b28b66418c373f30ffece5a58a734edfe5c5"
      score = 75
   strings:
      $s1 = "MSASN1.dll" fullword ascii
      $s2 = "&\";u\"s:\\" fullword ascii
      $s3 = "GetConsoleAliasA" fullword ascii
      $s4 = "kluzksghetriytre" fullword ascii
      $s5 = "LocalLock" fullword ascii /* goodware: 1 */
      $s6 = "GetCalendarInfoA" fullword ascii
      $s7 = "\\|jp0m<F" fullword ascii
      $s8 = "uL1-~WEw" fullword ascii
      $s9 = "HH>x'jDZ" fullword ascii
      $s10 = "ASN1BERDecCheck" fullword ascii
      $s11 = "ASN1BERDecSkip" fullword ascii
      $s12 = "Dhy4Wfy-" fullword ascii
      $s13 = " pMK(}LLl" fullword ascii
      $s14 = "xoI^:,rX" fullword ascii
      $s15 = "IpqO,Myba" fullword ascii
      $s16 = "gNJZg$H'" fullword ascii
      $s17 = "1ViM.Ej!%" fullword ascii
      $s18 = "n'PU/oT\\o" fullword ascii
      $s19 = "68PfSH3q5" fullword ascii
      $s20 = "+b)WaljZ" fullword ascii
   condition:
      8 of ($s*)
}

rule sig_278e64142df7b133305e24e96b8f9d891ec4588dd44e0152f40095701374f7a1 {
   meta:
      description = "fakeav - file 278e64142df7b133305e24e96b8f9d891ec4588dd44e0152f40095701374f7a1.exe"
      author = "yarGen-Go"
      date = "2026-09-04"
      hash1 = "278e64142df7b133305e24e96b8f9d891ec4588dd44e0152f40095701374f7a1"
      score = 75
   strings:
      $s1 = "MSASN1.dll" fullword ascii
      $s2 = "&\";u\"s:\\" fullword ascii
      $s3 = "GetConsoleAliasA" fullword ascii
      $s4 = "kluzksghetriytre" fullword ascii
      $s5 = "LocalLock" fullword ascii /* goodware: 1 */
      $s6 = "GetCalendarInfoA" fullword ascii
      $s7 = "\\|jp0m<F" fullword ascii
      $s8 = "tlUsO+3r" fullword ascii
      $s9 = "Rhk*`snsJf" fullword ascii
      $s10 = "ASN1BERDecSkip" fullword ascii
      $s11 = "ASN1BEREncLength" fullword ascii
      $s12 = "ASN1BERDecCheck" fullword ascii
      $s13 = "ASN1BERDecEoid" fullword ascii
      $s14 = "Dhy4Wfy-" fullword ascii
      $s15 = " pMK(}LLl" fullword ascii
      $s16 = "xoI^:,rX" fullword ascii
      $s17 = "IpqO,Myba" fullword ascii
      $s18 = "gNJZg$H'" fullword ascii
      $s19 = "1ViM.Ej!%" fullword ascii
      $s20 = "n'PU/oT\\o" fullword ascii
   condition:
      8 of ($s*)
}

/* Super Rules ------------------------------------------------------------- */

rule sig_1ad0e3f2fee448eb3efa7b0b4408b28b66418c373f30ffece5a58a734edfe5c5_278e64142df7b133305e24e96b8f9d891ec_super {
   meta:
      description = "fakeav - from files 1ad0e3f2fee448eb3efa7b0b4408b28b66418c373f30ffece5a58a734edfe5c5.exe, 278e64142df7b133305e24e96b8f9d891ec4588dd44e0152f40095701374f7a1.exe"
      author = "yarGen-Go"
      date = "2026-09-04"
      hash1 = "1ad0e3f2fee448eb3efa7b0b4408b28b66418c373f30ffece5a58a734edfe5c5"
      hash2 = "278e64142df7b133305e24e96b8f9d891ec4588dd44e0152f40095701374f7a1"
      score = 75
   strings:
      $s1 = "&\";u\"s:\\" fullword ascii
      $s2 = "GetConsoleAliasA" fullword ascii
      $s3 = "kluzksghetriytre" fullword ascii
      $s4 = "LocalLock" fullword ascii /* goodware: 1 */
      $s5 = "\\|jp0m<F" fullword ascii
      $s6 = "GetCalendarInfoA" fullword ascii
      $s7 = "Dhy4Wfy-" fullword ascii
      $s8 = "IpqO,Myba" fullword ascii
      $s9 = " pMK(}LLl" fullword ascii
      $s10 = "xoI^:,rX" fullword ascii
      $s11 = "gNJZg$H'" fullword ascii
      $s12 = "n'PU/oT\\o" fullword ascii
      $s13 = "1ViM.Ej!%" fullword ascii
      $s14 = "ASN1BERDecSkip" fullword ascii
   condition:
      (8 of ($s*))
      or (all of them)
}

/*
   YARA Rule Set
   Author: yarGen-Go
   Date: 2026-09-04
   Identifier: kryptik
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_3eafd449fb1c0adad1a8bb9ec7baad5ce37163c57c70e5b365eed7ec646e843e {
   meta:
      description = "kryptik - file 3eafd449fb1c0adad1a8bb9ec7baad5ce37163c57c70e5b365eed7ec646e843e.exe"
      author = "yarGen-Go"
      date = "2026-09-04"
      hash1 = "3eafd449fb1c0adad1a8bb9ec7baad5ce37163c57c70e5b365eed7ec646e843e"
      score = 75
   strings:
      $s1 = "\\system32\\cabinet.dll" fullword ascii
      $s2 = "DFDWiz.exe" fullword wide
      $s3 = "<requestedExecutionLevel" fullword ascii /* goodware: 3 */
      $s4 = "publicKeyToken=\"6595b64144ccf1df\"" fullword ascii /* goodware: 1 */
      $s5 = "UserHandleGrantAccess" fullword ascii /* goodware: 1 */
      $s6 = "3333333333" fullword ascii /* goodware: 3, reversed encoded */
      $s7 = "version=\"1.0.0.0\"" fullword ascii /* goodware: 1 */
      $s8 = "version=\"6.0.0.0\"" fullword ascii /* goodware: 1 */
      $s9 = "GetComboBoxInfo" fullword ascii /* goodware: 2 */
      $s10 = "processorArchitecture=\"x86\"" fullword ascii /* goodware: 5 */
      $s11 = "name=\"Microsoft.Windows.Common-Controls\"" fullword ascii /* goodware: 1 */
      $s12 = "DdeGetLastError" fullword ascii /* goodware: 3 */
      $s13 = "<description>Windows Hard Disk Diagnosis Wizard</description>" fullword ascii /* goodware: 1 */
      $s14 = "    <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\"> " fullword ascii /* goodware: 3 */
      $s15 = "GetUserObjectSecurity" fullword ascii /* goodware: 3 */
      $s16 = "PostThreadMessageA" fullword ascii /* goodware: 4 */
      $s17 = "DialogBoxIndirectParamW" fullword ascii /* goodware: 1 */
      $s18 = "CreateDialogIndirectParamA" fullword ascii /* goodware: 7 */
      $s19 = "GetCursorInfo" fullword ascii /* goodware: 1 */
      $s20 = "FileDescription" fullword wide /* goodware: 2 */
   condition:
      8 of ($s*)
}

rule sig_47772d4047014f4d9c3a8f375de1345694b018de0eff325967f59b81804fb81e {
   meta:
      description = "kryptik - file 47772d4047014f4d9c3a8f375de1345694b018de0eff325967f59b81804fb81e.exe"
      author = "yarGen-Go"
      date = "2026-09-04"
      hash1 = "47772d4047014f4d9c3a8f375de1345694b018de0eff325967f59b81804fb81e"
      score = 75
   strings:
      $s1 = "1system32\\cscript.exe" fullword wide
      $s2 = "NThe winhlp32.exe binary in the Windows directory is corrupt, please reinstall.RIncorrect executable name, must be winhlp32.exe," fullword wide
      $s3 = "WINHLP32.EXE" fullword wide
      $s4 = "WM_COMMAND" fullword ascii /* goodware: 1 */
      $s5 = "FileDescription" fullword wide /* goodware: 2 */
      $s6 = "Microsoft(R) Windows (R) 2000 Operating System" fullword wide
      $s7 = "cvcvb.dxz" fullword ascii
      $s8 = "Translation" fullword wide /* goodware: 1 */
      $s9 = "InternalName" fullword wide /* goodware: 1 */
      $s10 = "LegalCopyright" fullword wide /* goodware: 1 */
      $s11 = "OriginalFilename" fullword wide /* goodware: 1 */
      $s12 = "WM_DRAWITEM" fullword ascii /* goodware: 1 */
      $s13 = "VS_VERSION_INFO" fullword wide
      $s14 = "pr*4el I.xxH" fullword ascii
      $s15 = "La>NOe.Eeo#\\el(" fullword ascii
      $s16 = "WCLnnD\\{2048EEE6-7FA2-11D0-9E6A-00A0C9138C29}\\VersionIndependentProgID" fullword wide
      $s17 = "negOpenKeyW" fullword ascii
      $s18 = "CompanyName" fullword wide
      $s19 = "FileVersion" fullword wide
      $s20 = "AUTOCHECKBOX" fullword ascii
   condition:
      8 of ($s*)
}

rule sig_543101fe0616e5258ab9237a44c5fd8eae2ab59c2c93e688e0e7156275606003 {
   meta:
      description = "kryptik - file 543101fe0616e5258ab9237a44c5fd8eae2ab59c2c93e688e0e7156275606003.exe"
      author = "yarGen-Go"
      date = "2026-09-04"
      hash1 = "543101fe0616e5258ab9237a44c5fd8eae2ab59c2c93e688e0e7156275606003"
      score = 75
   strings:
      $s1 = "\\system32\\cabinet.dll" fullword ascii
      $s2 = "DFDWiz.exe" fullword wide
      $s3 = "GetProcessDefaultLayout" fullword ascii
      $s4 = "<requestedExecutionLevel" fullword ascii /* goodware: 3 */
      $s5 = "GetShellWindow" fullword ascii /* goodware: 2 */
      $s6 = "publicKeyToken=\"6595b64144ccf1df\"" fullword ascii /* goodware: 1 */
      $s7 = "3333333333" fullword ascii /* goodware: 3, reversed encoded */
      $s8 = "version=\"6.0.0.0\"" fullword ascii /* goodware: 1 */
      $s9 = "version=\"1.0.0.0\"" fullword ascii /* goodware: 1 */
      $s10 = "SHGetThreadRef" fullword ascii /* goodware: 1 */
      $s11 = "processorArchitecture=\"x86\"" fullword ascii /* goodware: 5 */
      $s12 = "name=\"Microsoft.Windows.Common-Controls\"" fullword ascii /* goodware: 1 */
      $s13 = "    <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\"> " fullword ascii /* goodware: 3 */
      $s14 = "<description>Windows Hard Disk Diagnosis Wizard</description>" fullword ascii /* goodware: 1 */
      $s15 = "GetUserObjectSecurity" fullword ascii /* goodware: 3 */
      $s16 = "PostThreadMessageA" fullword ascii /* goodware: 4 */
      $s17 = "GetOpenClipboardWindow" fullword ascii /* goodware: 1 */
      $s18 = "FileDescription" fullword wide /* goodware: 2 */
      $s19 = "GetCursorInfo" fullword ascii /* goodware: 1 */
      $s20 = "GetClipboardFormatNameA" fullword ascii /* goodware: 2 */
   condition:
      8 of ($s*)
}

/* Super Rules ------------------------------------------------------------- */

rule sig_3eafd449fb1c0adad1a8bb9ec7baad5ce37163c57c70e5b365eed7ec646e843e_543101fe0616e5258ab9237a44c5fd8eae2_super {
   meta:
      description = "kryptik - from files 3eafd449fb1c0adad1a8bb9ec7baad5ce37163c57c70e5b365eed7ec646e843e.exe, 543101fe0616e5258ab9237a44c5fd8eae2ab59c2c93e688e0e7156275606003.exe"
      author = "yarGen-Go"
      date = "2026-09-04"
      hash1 = "3eafd449fb1c0adad1a8bb9ec7baad5ce37163c57c70e5b365eed7ec646e843e"
      hash2 = "543101fe0616e5258ab9237a44c5fd8eae2ab59c2c93e688e0e7156275606003"
      score = 75
   strings:
      $s1 = "\\system32\\cabinet.dll" fullword ascii
      $s2 = "DFDWiz.exe" fullword wide
      $s3 = "<requestedExecutionLevel" fullword ascii /* goodware: 3 */
      $s4 = "publicKeyToken=\"6595b64144ccf1df\"" fullword ascii /* goodware: 1 */
      $s5 = "version=\"1.0.0.0\"" fullword ascii /* goodware: 1 */
      $s6 = "3333333333" fullword ascii /* goodware: 3, reversed encoded */
      $s7 = "version=\"6.0.0.0\"" fullword ascii /* goodware: 1 */
      $s8 = "processorArchitecture=\"x86\"" fullword ascii /* goodware: 5 */
      $s9 = "name=\"Microsoft.Windows.Common-Controls\"" fullword ascii /* goodware: 1 */
      $s10 = "GetUserObjectSecurity" fullword ascii /* goodware: 3 */
      $s11 = "    <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\"> " fullword ascii /* goodware: 3 */
      $s12 = "<description>Windows Hard Disk Diagnosis Wizard</description>" fullword ascii /* goodware: 1 */
      $s13 = "PostThreadMessageA" fullword ascii /* goodware: 4 */
      $s14 = "GetCursorInfo" fullword ascii /* goodware: 1 */
   condition:
      (8 of ($s*))
      or (all of them)
}

/*
   YARA Rule Set
   Author: yarGen-Go
   Date: 2026-09-04
   Identifier: mediyes
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_02137a839aaec764236e42cf1e944139184ce81d3c89e722fd5b99e94a6146c9 {
   meta:
      description = "mediyes - file 02137a839aaec764236e42cf1e944139184ce81d3c89e722fd5b99e94a6146c9.exe"
      author = "yarGen-Go"
      date = "2026-09-04"
      hash1 = "02137a839aaec764236e42cf1e944139184ce81d3c89e722fd5b99e94a6146c9"
      score = 75
   strings:
      $s1 = "TEPSERVICE.dll" fullword ascii
      $s2 = "\\ntdll.dll" fullword wide
      $s3 = "FileDescription" fullword wide /* goodware: 2 */
      $s4 = "TSPI_lineGetAddressStatus" fullword ascii
      $s5 = "KERNEL32.DLL" fullword ascii /* goodware: 16 */
      $s6 = "TUISPI_lineConfigDialog" fullword ascii
      $s7 = "TSPI_lineGetNumAddressIDs" fullword ascii
      $s8 = ".?AVrange_error@std@@" fullword ascii /* goodware: 2 */
      $s9 = ":$:,:L:T:\\:d:l:t:|:" fullword ascii
      $s10 = ".?AVServer@pipeIPC@@" fullword ascii
      $s11 = "7L:P:T:X:\\:`:|:" fullword ascii
      $s12 = ":X:\\:`:h:l:" fullword ascii
      $s13 = ": :$:P:X:\\:" fullword ascii
      $s14 = "Translation" fullword wide /* goodware: 1 */
      $s15 = "TSPI_lineGetLineDevStatus" fullword ascii
      $s16 = "TSPI_providerGenericDialogData" fullword ascii
      $s17 = "Kernel32.dll" fullword ascii /* goodware: 19 */
      $s18 = "TSPI_lineGetID" fullword ascii
      $s19 = "9$909P9X9`9l9" fullword ascii /* goodware: 1 */
      $s20 = "5,545@5`5l5" fullword ascii /* goodware: 1 */
   condition:
      8 of ($s*)
}

rule sig_2585ff9e7e41c34bbfeb22dd863362119a2577fe986cad1195dc7fe7148d5856 {
   meta:
      description = "mediyes - file 2585ff9e7e41c34bbfeb22dd863362119a2577fe986cad1195dc7fe7148d5856.exe"
      author = "yarGen-Go"
      date = "2026-09-04"
      hash1 = "2585ff9e7e41c34bbfeb22dd863362119a2577fe986cad1195dc7fe7148d5856"
      score = 75
   strings:
      $s1 = "svchost.exe" fullword wide
      $s2 = "wkssvc.dll" fullword wide
      $s3 = "wssl.dll" fullword wide
      $s4 = "r\\ntdll.dll" fullword wide
      $s5 = "Workstation Service Loader" fullword wide
      $s6 = "SvchostPushServiceGlobals" fullword ascii /* goodware: 1 */
      $s7 = "dCorExitProcess" fullword ascii
      $s8 = "\\\\.\\Global\\" fullword wide
      $s9 = "FileDescription" fullword wide /* goodware: 2 */
      $s10 = "KERNEL32.DLL" fullword ascii /* goodware: 16 */
      $s11 = "parse error" fullword ascii /* goodware: 3 */
      $s12 = "Translation" fullword wide /* goodware: 1 */
      $s13 = ":(:8:<:L:P:T:\\:t:" fullword ascii
      $s14 = "7(747T7`7" fullword ascii /* goodware: 1 */
      $s15 = "LegalCopyright" fullword wide /* goodware: 1 */
      $s16 = "5&565F5V5f5v5" fullword ascii /* goodware: 1 */
      $s17 = "1,1L1T1\\1d1l1t1|1" fullword ascii /* goodware: 1 */
      $s18 = "1,181@1X1d1" fullword ascii /* goodware: 1 */
      $s19 = "2$2,2D2P2p2|2" fullword ascii /* goodware: 1 */
      $s20 = "808<8\\8h8" fullword ascii /* goodware: 1 */
   condition:
      8 of ($s*)
}

rule sig_61083ebb038d6ff1d64c75bd1b18825a58c4c31741cadf45d776a2cbaeb13335 {
   meta:
      description = "mediyes - file 61083ebb038d6ff1d64c75bd1b18825a58c4c31741cadf45d776a2cbaeb13335.exe"
      author = "yarGen-Go"
      date = "2026-09-04"
      hash1 = "61083ebb038d6ff1d64c75bd1b18825a58c4c31741cadf45d776a2cbaeb13335"
      score = 75
   strings:
      $s1 = "TEPSERVICE.dll" fullword ascii
      $s2 = "\\ntdll.dll" fullword wide
      $s3 = "FileDescription" fullword wide /* goodware: 2 */
      $s4 = "TSPI_lineGetAddressStatus" fullword ascii
      $s5 = "KERNEL32.DLL" fullword ascii /* goodware: 16 */
      $s6 = "TUISPI_lineConfigDialog" fullword ascii
      $s7 = "TSPI_lineGetNumAddressIDs" fullword ascii
      $s8 = ".?AVrange_error@std@@" fullword ascii /* goodware: 2 */
      $s9 = ":$:,:L:T:\\:d:l:t:|:" fullword ascii
      $s10 = ".?AVServer@pipeIPC@@" fullword ascii
      $s11 = "7L:P:T:X:\\:`:|:" fullword ascii
      $s12 = ":X:\\:`:h:l:" fullword ascii
      $s13 = ": :$:P:X:\\:" fullword ascii
      $s14 = "Translation" fullword wide /* goodware: 1 */
      $s15 = "TSPI_lineGetLineDevStatus" fullword ascii
      $s16 = "TSPI_providerGenericDialogData" fullword ascii
      $s17 = "Kernel32.dll" fullword ascii /* goodware: 19 */
      $s18 = "TSPI_lineGetID" fullword ascii
      $s19 = "9$909P9X9`9l9" fullword ascii /* goodware: 1 */
      $s20 = "5,545@5`5l5" fullword ascii /* goodware: 1 */
   condition:
      8 of ($s*)
}

/* Super Rules ------------------------------------------------------------- */

rule sig_02137a839aaec764236e42cf1e944139184ce81d3c89e722fd5b99e94a6146c9_61083ebb038d6ff1d64c75bd1b18825a58c_super {
   meta:
      description = "mediyes - from files 02137a839aaec764236e42cf1e944139184ce81d3c89e722fd5b99e94a6146c9.exe, 61083ebb038d6ff1d64c75bd1b18825a58c4c31741cadf45d776a2cbaeb13335.exe"
      author = "yarGen-Go"
      date = "2026-09-04"
      hash1 = "02137a839aaec764236e42cf1e944139184ce81d3c89e722fd5b99e94a6146c9"
      hash2 = "61083ebb038d6ff1d64c75bd1b18825a58c4c31741cadf45d776a2cbaeb13335"
      score = 75
   strings:
      $s1 = "TEPSERVICE.dll" fullword ascii
      $s2 = "\\ntdll.dll" fullword wide
      $s3 = "TSPI_lineGetNumAddressIDs" fullword ascii
      $s4 = "TUISPI_lineConfigDialog" fullword ascii
      $s5 = "TSPI_lineGetAddressStatus" fullword ascii
      $s6 = ": :$:P:X:\\:" fullword ascii
      $s7 = ".?AVServer@pipeIPC@@" fullword ascii
      $s8 = ":$:,:L:T:\\:d:l:t:|:" fullword ascii
      $s9 = "7L:P:T:X:\\:`:|:" fullword ascii
      $s10 = ":X:\\:`:h:l:" fullword ascii
      $s11 = ".?AVrange_error@std@@" fullword ascii /* goodware: 2 */
      $s12 = "TSPI_providerGenericDialogData" fullword ascii
      $s13 = "TSPI_lineGetID" fullword ascii
      $s14 = "TSPI_lineGetLineDevStatus" fullword ascii
      $s15 = "Kernel32.dll" fullword ascii /* goodware: 19 */
      $s16 = "9$909P9X9`9l9" fullword ascii /* goodware: 1 */
      $s17 = "5,545@5`5l5" fullword ascii /* goodware: 1 */
   condition:
      (8 of ($s*))
      or (all of them)
}

/*
   YARA Rule Set
   Author: yarGen-Go
   Date: 2026-09-04
   Identifier: sirefef
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_4a9e7e209193da1dfcbdc04d939f9ac3238e16d92e74e19fbad7d08b8d8f64f1 {
   meta:
      description = "sirefef - file 4a9e7e209193da1dfcbdc04d939f9ac3238e16d92e74e19fbad7d08b8d8f64f1.exe"
      author = "yarGen-Go"
      date = "2026-09-04"
      hash1 = "4a9e7e209193da1dfcbdc04d939f9ac3238e16d92e74e19fbad7d08b8d8f64f1"
      score = 75
   strings:
      $s1 = "psapi.dll" fullword ascii /* goodware: 3 */
      $s2 = "SetupFile.exe" fullword wide
      $s3 = "GetDialogBaseUnits" fullword ascii /* goodware: 2 */
      $s4 = "FileDescription" fullword wide /* goodware: 2 */
      $s5 = "C:\\Folder of Working Project\\ProjectTest" fullword ascii
      $s6 = "Translation" fullword wide /* goodware: 1 */
      $s7 = "TODO: <File%description>" fullword wide
      $s8 = "ghhgytfjhytuj" fullword ascii
      $s9 = "OriginalFilename" fullword wide /* goodware: 1 */
      $s10 = "LegalCopyright" fullword wide /* goodware: 1 */
      $s11 = "ytqrhgfgfgd" fullword ascii
      $s12 = "InternalName" fullword wide /* goodware: 1 */
      $s13 = "fyghtryutrhgfhfg" fullword ascii
      $s14 = "dseqrfetreggfg" fullword ascii
      $s15 = "iryujyhggfhg" fullword ascii
      $s16 = "rtrgfdgf" fullword ascii
      $s17 = "Xch&qcomd" fullword wide
      $s18 = "VS_VERSION_INFO" fullword wide
      $s19 = "T_j.x.XiZ" fullword ascii
      $s20 = "FileVersion" fullword wide
   condition:
      8 of ($s*)
}

rule sig_659b7c3a678635b80d0ea9f7854af9b56ab8713d9a1c39c0a337f340aff0618c {
   meta:
      description = "sirefef - file 659b7c3a678635b80d0ea9f7854af9b56ab8713d9a1c39c0a337f340aff0618c.exe"
      author = "yarGen-Go"
      date = "2026-09-04"
      hash1 = "659b7c3a678635b80d0ea9f7854af9b56ab8713d9a1c39c0a337f340aff0618c"
      score = 75
   strings:
      $s1 = "MSVCRT.dll" fullword ascii /* goodware: 2 */
      $s2 = "comdlg32.dll" fullword ascii /* goodware: 9 */
      $s3 = "Q:\\xXmcfvgzt\\EFJbjgah\\jwlbdhpabwe.pdb" fullword ascii
      $s4 = "MapVirtualKeyExW" fullword ascii /* goodware: 2 */
      $s5 = "ClearCommError" fullword ascii /* goodware: 1 */
      $s6 = "GetComputerNameA" fullword ascii /* goodware: 4 */
      $s7 = "GetFontData" fullword ascii /* goodware: 2 */
      $s8 = "GetMessageExtraInfo" fullword ascii /* goodware: 2 */
      $s9 = "ImageList_GetIcon" fullword ascii /* goodware: 2 */
      $s10 = "GetNextDlgGroupItem" fullword ascii /* goodware: 3 */
      $s11 = "SetCommTimeouts" fullword ascii /* goodware: 1 */
      $s12 = "GetKeyboardType" fullword ascii /* goodware: 6 */
      $s13 = "GetMenuStringA" fullword ascii /* goodware: 4 */
      $s14 = "CreateRemoteThread" fullword ascii /* goodware: 5 */
      $s15 = "HHS7GFx9dw3f.top" fullword ascii
      $s16 = "GetClipCursor" fullword ascii
      $s17 = "SetThreadContext" fullword ascii /* goodware: 3 */
      $s18 = "PrintDlgW" fullword ascii /* goodware: 1 */
      $s19 = "ChooseFontW" fullword ascii /* goodware: 1 */
      $s20 = "CreateMailslotW" fullword ascii /* goodware: 1 */
   condition:
      8 of ($s*)
}

rule af29c6d25d15e878eb406276fe695017491f079509bbf5b2434fe975e4574679 {
   meta:
      description = "sirefef - file af29c6d25d15e878eb406276fe695017491f079509bbf5b2434fe975e4574679.exe"
      author = "yarGen-Go"
      date = "2026-09-04"
      hash1 = "af29c6d25d15e878eb406276fe695017491f079509bbf5b2434fe975e4574679"
      score = 75
   strings:
      $s1 = "PhysXCooking.dll" fullword wide
      $s2 = "FileDescription" fullword wide /* goodware: 2 */
      $s3 = "SetupComm" fullword ascii /* goodware: 1 */
      $s4 = "GlobalGetAtomNameA" fullword ascii /* goodware: 3 */
      $s5 = "Translation" fullword wide /* goodware: 1 */
      $s6 = "C:\\CurrentData\\Modify\\ApplicationNew" fullword ascii
      $s7 = "frdetgdgtfhgfjkmgj" fullword ascii
      $s8 = "OriginalFilename" fullword wide /* goodware: 1 */
      $s9 = "LegalCopyright" fullword wide /* goodware: 1 */
      $s10 = "InternalName" fullword wide /* goodware: 1 */
      $s11 = "gjhdhgjjlkhfghgf" fullword ascii
      $s12 = "ddfsgyhtrytrghf" fullword ascii
      $s13 = "FileVersion" fullword wide
      $s14 = "CompanyName" fullword wide
      $s15 = "VS_VERSION_INFO" fullword wide
      $s16 = "nX{?\"-%I&" fullword ascii
      $s17 = "Bddfsgyhtrytrghf" fullword wide
      $s18 = "\\bzF?0`$" fullword ascii
      $s19 = "NVIDIA Corporation" fullword wide /* goodware: 4 */
      $s20 = "OpenFileMappingA" fullword ascii /* goodware: 5 */
   condition:
      8 of ($s*)
}

/* Super Rules ------------------------------------------------------------- */

rule sig_4a9e7e209193da1dfcbdc04d939f9ac3238e16d92e74e19fbad7d08b8d8f64f1_af29c6d25d15e878eb406276fe695017491_super {
   meta:
      description = "sirefef - from files 4a9e7e209193da1dfcbdc04d939f9ac3238e16d92e74e19fbad7d08b8d8f64f1.exe, af29c6d25d15e878eb406276fe695017491f079509bbf5b2434fe975e4574679.exe"
      author = "yarGen-Go"
      date = "2026-09-04"
      hash1 = "4a9e7e209193da1dfcbdc04d939f9ac3238e16d92e74e19fbad7d08b8d8f64f1"
      hash2 = "af29c6d25d15e878eb406276fe695017491f079509bbf5b2434fe975e4574679"
      score = 75
   strings:
      $s1 = "FileDescription" fullword wide /* goodware: 2 */
      $s2 = "Translation" fullword wide /* goodware: 1 */
      $s3 = "OriginalFilename" fullword wide /* goodware: 1 */
      $s4 = "LegalCopyright" fullword wide /* goodware: 1 */
      $s5 = "InternalName" fullword wide /* goodware: 1 */
      $s6 = "FileVersion" fullword wide
      $s7 = "VS_VERSION_INFO" fullword wide
   condition:
      (all of ($s*))
      or (all of them)
}

/*
   YARA Rule Set
   Author: yarGen-Go
   Date: 2026-09-04
   Identifier: upatre
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_620bae1ab9de6fa46fe9eae40169f00e74374d9df32bc87c1a6a2954a70a6dce {
   meta:
      description = "upatre - file 620bae1ab9de6fa46fe9eae40169f00e74374d9df32bc87c1a6a2954a70a6dce.exe"
      author = "yarGen-Go"
      date = "2026-09-04"
      hash1 = "620bae1ab9de6fa46fe9eae40169f00e74374d9df32bc87c1a6a2954a70a6dce"
      score = 75
   strings:
      $x1 = "C:\\Users\\hossam\\AppData\\Local\\Temp\\Rar$EXa0.639\\VAT_08102013.exe" fullword wide
      $s2 = "C:\\6u0NKEyd.exe" fullword wide
      $s3 = "C:\\_kTruNo8.exe" fullword wide
      $s4 = "c:\\work\\1765331\\b683bd78aed187dfbd9049ad3ecdb4d6.exe" fullword wide
      $s5 = "C:\\YNCDaNY0.exe" fullword wide
      $s6 = "C:\\88dS28W6.exe" fullword wide
      $s7 = "C:\\q2Zz7WXm.exe" fullword wide
      $s8 = "C:\\uhvVGsgz.exe" fullword wide
      $s9 = "C:\\lMranlwL.exe" fullword wide
      $s10 = "C:\\dxnDQlj_.exe" fullword wide
      $s11 = "C:\\rSBHKhr0.exe" fullword wide
      $s12 = "C:\\xir5XTjh.exe" fullword wide
      $s13 = "C:\\fB9MHJSr.exe" fullword wide
      $s14 = "C:\\rBveHbky.exe" fullword wide
      $s15 = "C:\\XiE2Pr93.exe" fullword wide
      $s16 = "C:\\gKoaq3Ph.exe" fullword wide
      $s17 = "C:\\1dSiUJhT.exe" fullword wide
      $s18 = "C:\\2ddWgei5.exe" fullword wide
      $s19 = "C:\\zz_RlXHE.exe" fullword wide
      $s20 = "C:\\sVhJQxLT.exe" fullword wide
   condition:
      1 of ($x*) and 4 of ($s*)
}

rule sig_65d985debfd483eb49b40c58a3ff22641391a7cd6122784b23d439c49d034bea {
   meta:
      description = "upatre - file 65d985debfd483eb49b40c58a3ff22641391a7cd6122784b23d439c49d034bea.exe"
      author = "yarGen-Go"
      date = "2026-09-04"
      hash1 = "65d985debfd483eb49b40c58a3ff22641391a7cd6122784b23d439c49d034bea"
      score = 75
   strings:
      $x1 = "C:\\Users\\delair\\AppData\\Local\\Temp\\Temp1_ACAS10092013_138554_5530.zip\\ACAS10092013.exe" fullword wide
      $s2 = "C:\\Downloads\\707ee2fda542041fddea70cd116b0181.exe" fullword wide
      $s3 = "C:\\x1OgiDPW.exe" fullword wide
      $s4 = "C:\\GmB4BqcD.exe" fullword wide
      $s5 = "C:\\RKXbaZZj.exe" fullword wide
      $s6 = "C:\\0hFYN63M.exe" fullword wide
      $s7 = "C:\\5RFCBqlv.exe" fullword wide
      $s8 = "C:\\vqvVY0Yh.exe" fullword wide
      $s9 = "C:\\idREFuu1.exe" fullword wide
      $s10 = "C:\\DPesPJ_C.exe" fullword wide
      $s11 = "C:\\LDynOu_S.exe" fullword wide
      $s12 = "C:\\5lMG7X3q.exe" fullword wide
      $s13 = "C:\\2F9rZYEh.exe" fullword wide
      $s14 = "C:\\p0vD0F1q.exe" fullword wide
      $s15 = "C:\\6JOCy4VX.exe" fullword wide
      $s16 = "C:\\PDxIlIjX.exe" fullword wide
      $s17 = "processorArchitecture=\"X86\"" fullword ascii /* goodware: 1 */
      $s18 = "gdi32.dll" fullword ascii /* goodware: 9 */
      $s19 = "publicKeyToken=\"6595b64144ccf1df\"" fullword ascii /* goodware: 1 */
      $s20 = "version=\"6.0.0.0\"" fullword ascii /* goodware: 1 */
   condition:
      1 of ($x*) and 4 of ($s*)
}

rule sig_6c9feb09c2f76717829b2696c2ebe59d11b2ce69d4bccf698fd3aa0ba5c3fd21 {
   meta:
      description = "upatre - file 6c9feb09c2f76717829b2696c2ebe59d11b2ce69d4bccf698fd3aa0ba5c3fd21.exe"
      author = "yarGen-Go"
      date = "2026-09-04"
      hash1 = "6c9feb09c2f76717829b2696c2ebe59d11b2ce69d4bccf698fd3aa0ba5c3fd21"
      score = 75
   strings:
      $s1 = "C:\\Downloads\\34b2f077658a5004c3a79c1f71e0cb5c.exe" fullword wide
      $s2 = "C:\\Downloads\\a505ce73901a4e11789e8697bb89ba1b.exe" fullword wide
      $s3 = "C:\\Downloads\\ba75e000012b80e7f563692307ab9e23.exe" fullword wide
      $s4 = "C:\\DOCUME~1\\exp1\\LOCALS~1\\Temp\\Rar$EX00.796\\USPS_Label_03102013.exe" fullword wide
      $s5 = "gdi32.dll" fullword ascii /* goodware: 9 */
      $s6 = "Translation" fullword wide /* goodware: 1 */
      $s7 = "prev.inf" fullword ascii
      $s8 = "xxxtttttt" fullword ascii
      $s9 = "IDR_VERSION1" fullword wide
      $s10 = "CompanyName" fullword wide
      $s11 = "FileVersion" fullword wide
      $s12 = "VS_VERSION_INFO" fullword wide
      $s13 = "uno momento" fullword ascii
      $s14 = ">+>Q>a>n>t>z>" fullword ascii
      $s15 = "ProductVersion" fullword wide /* goodware: 8 */
      $s16 = "2!2%2)2-21252=2A2" fullword ascii
      $s17 = ":D;N;R;X;b;l;x;" fullword ascii
      $s18 = "9-9<9a9z9" fullword ascii
      $s19 = "FFFF04E3" fullword wide
      $s20 = "8&8N8T8s8x8" fullword ascii
   condition:
      8 of ($s*)
}

/*
   YARA Rule Set
   Author: yarGen-Go
   Date: 2026-09-04
   Identifier: zbot
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_0d7f9a2daa3ce1ff75b726e758d99d622ac6e4c77ec216fc90853c356734dc76 {
   meta:
      description = "zbot - file 0d7f9a2daa3ce1ff75b726e758d99d622ac6e4c77ec216fc90853c356734dc76.exe"
      author = "yarGen-Go"
      date = "2026-09-04"
      hash1 = "0d7f9a2daa3ce1ff75b726e758d99d622ac6e4c77ec216fc90853c356734dc76"
      score = 75
   strings:
      $s1 = "GetProcessVersion" fullword ascii
      $s2 = "GetSystemPowerStatus" fullword ascii /* goodware: 2 */
      $s3 = "GetProcessAffinityMask" fullword ascii /* goodware: 4 */
      $s4 = "Twain.dll Client's 32-Bit Thunking Server" fullword wide
      $s5 = "Twunk_32.exe" fullword wide
      $s6 = "UserHandleGrantAccess" fullword ascii /* goodware: 1 */
      $s7 = "GetPrivateProfileSectionA" fullword ascii /* goodware: 1 */
      $s8 = "GetPrivateProfileStructA" fullword ascii /* goodware: 1 */
      $s9 = "GetCompressedFileSizeA" fullword ascii /* goodware: 2 */
      $s10 = "SetSystemPowerState" fullword ascii
      $s11 = "CreateNamedPipeA" fullword ascii /* goodware: 4 */
      $s12 = "DdeGetLastError" fullword ascii /* goodware: 3 */
      $s13 = "GetSystemWindowsDirectoryW" fullword ascii /* goodware: 4 */
      $s14 = "FileDescription" fullword wide /* goodware: 2 */
      $s15 = "GetCPInfoExA" fullword ascii /* goodware: 1 */
      $s16 = "ImageList_GetImageInfo" fullword ascii /* goodware: 1 */
      $s17 = "GetClipboardFormatNameA" fullword ascii /* goodware: 2 */
      $s18 = "DnsHostnameToComputerNameA" fullword ascii
      $s19 = "ChangeTimerQueueTimer" fullword ascii /* goodware: 2 */
      $s20 = "GetBinaryType" fullword ascii
   condition:
      8 of ($s*)
}

rule sig_1a7895c50ce00d72188e1ad764fc8ddc32d7f2e437e2edd10e9229807118e10f {
   meta:
      description = "zbot - file 1a7895c50ce00d72188e1ad764fc8ddc32d7f2e437e2edd10e9229807118e10f.exe"
      author = "yarGen-Go"
      date = "2026-09-04"
      hash1 = "1a7895c50ce00d72188e1ad764fc8ddc32d7f2e437e2edd10e9229807118e10f"
      score = 75
   strings:
      $s1 = "GetProcessVersion" fullword ascii
      $s2 = "GetSystemPowerStatus" fullword ascii /* goodware: 2 */
      $s3 = "GetProcessAffinityMask" fullword ascii /* goodware: 4 */
      $s4 = "Twunk_32.exe" fullword wide
      $s5 = "Twain.dll Client's 32-Bit Thunking Server" fullword wide
      $s6 = "GetPrivateProfileStructA" fullword ascii /* goodware: 1 */
      $s7 = "GetPrivateProfileSectionA" fullword ascii /* goodware: 1 */
      $s8 = "UserHandleGrantAccess" fullword ascii /* goodware: 1 */
      $s9 = "GetCompressedFileSizeA" fullword ascii /* goodware: 2 */
      $s10 = "SetSystemPowerState" fullword ascii
      $s11 = "CreateNamedPipeA" fullword ascii /* goodware: 4 */
      $s12 = "DdeGetLastError" fullword ascii /* goodware: 3 */
      $s13 = "FileDescription" fullword wide /* goodware: 2 */
      $s14 = "GetCPInfoExA" fullword ascii /* goodware: 1 */
      $s15 = "ImageList_GetImageInfo" fullword ascii /* goodware: 1 */
      $s16 = "GetSystemWindowsDirectoryW" fullword ascii /* goodware: 4 */
      $s17 = "ChangeTimerQueueTimer" fullword ascii /* goodware: 2 */
      $s18 = "DnsHostnameToComputerNameA" fullword ascii
      $s19 = "WINNLSGetIMEHotkey" fullword ascii
      $s20 = "GetBinaryType" fullword ascii
   condition:
      8 of ($s*)
}

rule sig_94efa32b73992f69ed5a23f81a7c75f72e4fed6f877e48fc0c5c3b6bd8123c2f {
   meta:
      description = "zbot - file 94efa32b73992f69ed5a23f81a7c75f72e4fed6f877e48fc0c5c3b6bd8123c2f.exe"
      author = "yarGen-Go"
      date = "2026-09-04"
      hash1 = "94efa32b73992f69ed5a23f81a7c75f72e4fed6f877e48fc0c5c3b6bd8123c2f"
      score = 75
   strings:
      $s1 = "wwwwwwwwwwwwp" fullword ascii /* goodware: 4, reversed encoded */
      $s2 = "Translation" fullword wide /* goodware: 1 */
      $s3 = "GetuWs}F5" fullword ascii
      $s4 = "@EXzeYEkspD4kKFaa5fVJIj7Zmpzq5yoWIoGnKU" fullword wide
      $s5 = "SOFTWARE" fullword wide /* goodware: 2 */
      $s6 = "ase (r)  Host" fullword wide
      $s7 = "VS_VERSION_INFO" fullword wide
      $s8 = "VersionIndependentProgID" fullword wide
      $s9 = "\\y2Q>$HQr" fullword ascii
      $s10 = "9.qJ3:^T" fullword ascii
      $s11 = "1U>g1L6a1G>c1>6G1" fullword ascii
      $s12 = ";,3e94DO" fullword ascii
      $s13 = "Tswckr/dej" fullword ascii
      $s14 = "gmst,emA" fullword ascii
      $s15 = "j22gbml9" fullword ascii
      $s16 = "gbejsIeXv" fullword ascii
      $s17 = "vB#;n1pxu" fullword ascii
      $s18 = "H7cr[vZW" fullword ascii
      $s19 = "mWZi$9`x" fullword ascii
      $s20 = "&t]c&u]d&v]e&P]" fullword ascii
   condition:
      8 of ($s*)
}

/* Super Rules ------------------------------------------------------------- */

rule sig_0d7f9a2daa3ce1ff75b726e758d99d622ac6e4c77ec216fc90853c356734dc76_1a7895c50ce00d72188e1ad764fc8ddc32d_super {
   meta:
      description = "zbot - from files 0d7f9a2daa3ce1ff75b726e758d99d622ac6e4c77ec216fc90853c356734dc76.exe, 1a7895c50ce00d72188e1ad764fc8ddc32d7f2e437e2edd10e9229807118e10f.exe"
      author = "yarGen-Go"
      date = "2026-09-04"
      hash1 = "0d7f9a2daa3ce1ff75b726e758d99d622ac6e4c77ec216fc90853c356734dc76"
      hash2 = "1a7895c50ce00d72188e1ad764fc8ddc32d7f2e437e2edd10e9229807118e10f"
      score = 75
   strings:
      $s1 = "GetProcessVersion" fullword ascii
      $s2 = "GetSystemPowerStatus" fullword ascii /* goodware: 2 */
      $s3 = "GetProcessAffinityMask" fullword ascii /* goodware: 4 */
      $s4 = "Twunk_32.exe" fullword wide
      $s5 = "Twain.dll Client's 32-Bit Thunking Server" fullword wide
      $s6 = "GetPrivateProfileSectionA" fullword ascii /* goodware: 1 */
      $s7 = "UserHandleGrantAccess" fullword ascii /* goodware: 1 */
      $s8 = "GetPrivateProfileStructA" fullword ascii /* goodware: 1 */
      $s9 = "GetCompressedFileSizeA" fullword ascii /* goodware: 2 */
      $s10 = "DdeGetLastError" fullword ascii /* goodware: 3 */
      $s11 = "CreateNamedPipeA" fullword ascii /* goodware: 4 */
      $s12 = "SetSystemPowerState" fullword ascii
      $s13 = "GetSystemWindowsDirectoryW" fullword ascii /* goodware: 4 */
      $s14 = "FileDescription" fullword wide /* goodware: 2 */
      $s15 = "ImageList_GetImageInfo" fullword ascii /* goodware: 1 */
      $s16 = "GetCPInfoExA" fullword ascii /* goodware: 1 */
      $s17 = "DnsHostnameToComputerNameA" fullword ascii
      $s18 = "ChangeTimerQueueTimer" fullword ascii /* goodware: 2 */
      $s19 = "GetBinaryType" fullword ascii
   condition:
      (8 of ($s*))
      or (all of them)
}
