; Vigil's installer: per machine, in Program Files, with a Start menu shortcut that carries the
; app's AppUserModelID (Windows ties notifications to it) and an uninstaller.
;
;   makensis /DVERSION=2.0.0 /DEXE=C:\full\path\vigil.exe /DOUT=C:\full\path\Vigil_2.0.0_x64-setup.exe installer\vigil.nsi
;
; installer\test-installer.ps1 installs it, checks it, upgrades over it and uninstalls it (CI).
;
; makensis works in this folder, so relative paths are read from here: pass full paths.
;
; Vigil always goes to Program Files, where only administrators can write: the executable runs
; elevated, so a folder a standard user could change would let malware replace it. There is no
; folder choice, and /D and a stale InstallLocation are ignored.
;
; The program, its shortcut and the uninstall entry use the same names as earlier Vigil
; installers, so installing over an older version upgrades it in place; what those wrote and this
; one does not (a desktop shortcut, the vendor key) is removed by exact name. Vigil's data
; (%ProgramData%\Vigil: the journal and the quarantine; %LOCALAPPDATA%\Vigil) is kept: History and
; quarantined files must survive a reinstall.

Unicode true
ManifestDPIAware true
SetCompressor /SOLID lzma

!ifndef VERSION
  !error "Pass /DVERSION=x.y.z"
!endif
!ifndef EXE
  !error "Pass /DEXE=path\to\vigil.exe"
!endif
!ifndef OUT
  !define OUT "Vigil_${VERSION}_x64-setup.exe"
!endif
!ifndef ICON
  !define ICON "..\crates\vigil-app\icons\icon.ico"
!endif

!define APP "Vigil"
!define AUMID "com.andresayac.vigil"
!define PUBLISHER "andresayac"
!define UNINSTALL_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP}"
; Earlier installers kept the install folder and the installer language here.
!define VENDOR_KEY "Software\${PUBLISHER}"
!define OLD_PRODUCT_KEY "${VENDOR_KEY}\${APP}"

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "x64.nsh"

Name "${APP}"
OutFile "${OUT}"
InstallDir "$PROGRAMFILES64\${APP}"
RequestExecutionLevel admin
BrandingText "${APP} ${VERSION}"

VIProductVersion "${VERSION}.0"
VIFileVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "${APP}"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "FileDescription" "${APP} installer"
VIAddVersionKey "CompanyName" "${PUBLISHER}"
VIAddVersionKey "LegalCopyright" "${PUBLISHER}"

!define MUI_ICON "${ICON}"
!define MUI_UNICON "${ICON}"
!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_NOAUTOCLOSE

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_LANGUAGE "Spanish"
!insertmacro MUI_LANGUAGE "French"
!insertmacro MUI_LANGUAGE "PortugueseBR"
!insertmacro MUI_LANGUAGE "SimpChinese"

LangString RUNNING ${LANG_ENGLISH} "Vigil is running. Quit it from its icon in the notification area, then choose Retry."
LangString RUNNING ${LANG_SPANISH} "Vigil se está ejecutando. Ciérralo desde su icono en el área de notificación y elige Reintentar."
LangString RUNNING ${LANG_FRENCH} "Vigil est en cours d’exécution. Quittez-le depuis son icône dans la zone de notification, puis choisissez Réessayer."
LangString RUNNING ${LANG_PORTUGUESEBR} "O Vigil está em execução. Feche-o pelo ícone na área de notificação e escolha Repetir."
LangString RUNNING ${LANG_SIMPCHINESE} "Vigil 正在运行。请从通知区域的图标退出它，然后选择“重试”。"

LangString NEEDS64 ${LANG_ENGLISH} "Vigil needs 64-bit Windows 10 or 11."
LangString NEEDS64 ${LANG_SPANISH} "Vigil necesita Windows 10 u 11 de 64 bits."
LangString NEEDS64 ${LANG_FRENCH} "Vigil nécessite Windows 10 ou 11 en version 64 bits."
LangString NEEDS64 ${LANG_PORTUGUESEBR} "O Vigil precisa do Windows 10 ou 11 de 64 bits."
LangString NEEDS64 ${LANG_SIMPCHINESE} "Vigil 需要 64 位 Windows 10 或 11。"

; Sets System.AppUserModel.ID on a shortcut (IShellLinkW + IPersistFile + IPropertyStore).
!macro SetShortcutAumid LNK ID
  Push $0
  Push $1
  Push $2
  Push $3
  Push $4
  Push $5
  Push $6
  ; CLSID_ShellLink, CLSCTX_INPROC_SERVER, IID_IShellLinkW
  System::Call 'ole32::CoCreateInstance(g "{00021401-0000-0000-C000-000000000046}", p 0, i 1, g "{000214F9-0000-0000-C000-000000000046}", *p .r0) i .r1'
  ${If} $1 = 0
    ; IUnknown::QueryInterface(IID_IPersistFile)
    System::Call '$0->0(g "{0000010b-0000-0000-C000-000000000046}", *p .r2) i .r1'
    ${If} $1 = 0
      ; IPersistFile::Load(path, STGM_READWRITE)
      System::Call '$2->5(w "${LNK}", i 2) i .r1'
      ${If} $1 = 0
        ; IUnknown::QueryInterface(IID_IPropertyStore)
        System::Call '$0->0(g "{886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99}", *p .r3) i .r1'
        ${If} $1 = 0
          ; PKEY_AppUserModel_ID and a PROPVARIANT of type VT_LPWSTR
          System::Call '*(&g16 "{9F4C2855-9F79-4B39-A8D0-E1D42DE1D5F3}", i 5) p .r4'
          System::Call '*(&w${NSIS_MAX_STRLEN} "${ID}") p .r6'
          System::Call '*(&i2 31, &i2 0, &i2 0, &i2 0, p r6, p 0) p .r5'
          ; IPropertyStore::SetValue, IPropertyStore::Commit
          System::Call '$3->6(p r4, p r5) i .r1'
          ${If} $1 = 0
            System::Call '$3->7() i .r1'
          ${EndIf}
          System::Free $4
          System::Free $5
          System::Free $6
          System::Call '$3->2()'
          ; IPersistFile::Save(NULL, TRUE)
          ${If} $1 = 0
            System::Call '$2->6(p 0, i 1) i .r1'
          ${EndIf}
        ${EndIf}
      ${EndIf}
      System::Call '$2->2()'
    ${EndIf}
    System::Call '$0->2()'
  ${EndIf}
  Pop $6
  Pop $5
  Pop $4
  Pop $3
  Pop $2
  Pop $1
  Pop $0
!macroend

; What earlier installers wrote and this one does not, by exact name. Installing removes the vendor
; key (it held the old install folder and installer language; the key above it only if empty).
; Uninstalling also removes their desktop shortcut (all users and the account that uninstalls),
; which keeps working after an upgrade since the program's path does not change.
!macro OLD_KEYS
  DeleteRegKey HKLM "${OLD_PRODUCT_KEY}"
  DeleteRegKey /ifempty HKLM "${VENDOR_KEY}"
  DeleteRegKey HKCU "${OLD_PRODUCT_KEY}"
  DeleteRegKey /ifempty HKCU "${VENDOR_KEY}"
!macroend

Function RemoveOldLeftovers
  !insertmacro OLD_KEYS
FunctionEnd

; Vigil's data folder (%ProgramData%\Vigil), created when missing in one step with its
; permissions: owner Administrators, full control for Administrators and SYSTEM only, nothing
; inherited from ProgramData (where any user may create folders), so no program without
; administrator rights can create it first. An existing folder is left as it is: the app checks it
; at start and moves aside one it did not make. Needs SetShellVarContext all ($APPDATA is
; ProgramData then).
!define DATA_SDDL "O:BAD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)"
Function CreateDataFolder
  Push $0
  Push $1
  Push $2
  IfFileExists "$APPDATA\${APP}\*.*" done
  System::Call 'advapi32::ConvertStringSecurityDescriptorToSecurityDescriptorW(w "${DATA_SDDL}", i 1, *p .r0, p 0) i .r1'
  ${If} $1 <> 0
    ; SECURITY_ATTRIBUTES: nLength, lpSecurityDescriptor, bInheritHandle (with the padding of a
    ; 64-bit build).
    !if ${NSIS_PTR_SIZE} > 4
      System::Call '*(i 24, i 0, p r0, i 0, i 0) p .r2'
    !else
      System::Call '*(i 12, p r0, i 0) p .r2'
    !endif
    System::Call 'kernel32::CreateDirectoryW(w "$APPDATA\${APP}", p r2) i .r1'
    System::Free $2
    System::Call 'kernel32::LocalFree(p r0) p .r1'
  ${EndIf}
  done:
  Pop $2
  Pop $1
  Pop $0
FunctionEnd

Function un.RemoveOldLeftovers
  !insertmacro OLD_KEYS
  SetShellVarContext current
  Delete "$DESKTOP\${APP}.lnk"
  SetShellVarContext all
  Delete "$DESKTOP\${APP}.lnk"
FunctionEnd

Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP "$(NEEDS64)" /SD IDOK
    Abort
  ${EndIf}
  SetRegView 64
  ; Program Files only, whatever /D or an earlier install said.
  StrCpy $INSTDIR "$PROGRAMFILES64\${APP}"
  !insertmacro MUI_LANGDLL_DISPLAY
FunctionEnd

Section "Vigil" Main
  SectionIn RO
  SetRegView 64
  SetShellVarContext all
  StrCpy $INSTDIR "$PROGRAMFILES64\${APP}"
  SetOutPath "$INSTDIR"
  ; The running program cannot be replaced: ask to quit it and try again.
  retry:
  ClearErrors
  SetOverwrite try
  File "/oname=vigil.exe" "${EXE}"
  ${If} ${Errors}
    MessageBox MB_RETRYCANCEL|MB_ICONEXCLAMATION "$(RUNNING)" /SD IDCANCEL IDRETRY retry
    SetErrorLevel 2
    Abort
  ${EndIf}
  SetOverwrite on

  WriteUninstaller "$INSTDIR\uninstall.exe"

  CreateShortcut "$SMPROGRAMS\${APP}.lnk" "$INSTDIR\vigil.exe" "" "$INSTDIR\vigil.exe" 0
  !insertmacro SetShortcutAumid "$SMPROGRAMS\${APP}.lnk" "${AUMID}"

  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayName" "${APP}"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "Publisher" "${PUBLISHER}"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayIcon" "$INSTDIR\vigil.exe"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "${UNINSTALL_KEY}" "QuietUninstallString" '"$INSTDIR\uninstall.exe" /S'
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "NoRepair" 1
  ; Size in KB, for Installed apps.
  SectionGetSize ${Main} $0
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "EstimatedSize" $0

  ; Earlier installers' leftovers, by exact name.
  Call RemoveOldLeftovers

  Call CreateDataFolder
SectionEnd

Function un.onInit
  SetRegView 64
  !insertmacro MUI_UNGETLANGUAGE
FunctionEnd

Section "Uninstall"
  SetRegView 64
  SetShellVarContext all
  retry:
  ClearErrors
  Delete "$INSTDIR\vigil.exe"
  ${If} ${Errors}
    MessageBox MB_RETRYCANCEL|MB_ICONEXCLAMATION "$(RUNNING)" /SD IDCANCEL IDRETRY retry
    SetErrorLevel 2
    Abort
  ${EndIf}
  Delete "$SMPROGRAMS\${APP}.lnk"
  Call un.RemoveOldLeftovers
  ; The start at sign-in (Settings > Background watch) of the account that uninstalls.
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "${APP}"
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" "${APP}"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  DeleteRegKey HKLM "${UNINSTALL_KEY}"
SectionEnd
