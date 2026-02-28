Unicode false
RequestExecutionLevel admin
InstallDir "$PROGRAMFILES64\\ZeroTier\\One"
!ifdef OUTPUT_FILE
OutFile "${OUTPUT_FILE}"
!else
OutFile "ZeroTier-One-Cross-x64-Installer.exe"
!endif
Name "ZeroTier One (Cross Build x64)"
ShowInstDetails show
ShowUninstDetails show
SetCompressor /SOLID lzma

!include "LogicLib.nsh"
!include "x64.nsh"

!ifndef STAGE_DIR
  !error "STAGE_DIR is required"
!endif

Section "Install"
  SetShellVarContext all

  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP "This installer requires 64-bit Windows."
    Abort
  ${EndIf}

  CreateDirectory "$INSTDIR"
  SetOutPath "$INSTDIR"

  File "${STAGE_DIR}/zerotier-one_x64.exe"
  File "${STAGE_DIR}/zerotier-cli.bat"
  File "${STAGE_DIR}/zerotier-idtool.bat"

  CreateDirectory "$APPDATA\\ZeroTier\\One"
  SetOutPath "$APPDATA\\ZeroTier\\One"
  File "${STAGE_DIR}/zttap300.inf"
  File "${STAGE_DIR}/zttap300.sys"
  File "${STAGE_DIR}/zttap300.cat"

  WriteUninstaller "$INSTDIR\\Uninstall.exe"

  WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\ZeroTierOneCross" "DisplayName" "ZeroTier One (Cross Build x64)"
  WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\ZeroTierOneCross" "UninstallString" "$INSTDIR\\Uninstall.exe"
  WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\ZeroTierOneCross" "InstallLocation" "$INSTDIR"
  WriteRegDWORD HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\ZeroTierOneCross" "NoModify" 1
  WriteRegDWORD HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\ZeroTierOneCross" "NoRepair" 1

  nsExec::ExecToLog '"$INSTDIR\\zerotier-one_x64.exe" -I'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "Service installation failed (exit code $0)."
    Abort
  ${EndIf}

  nsExec::ExecToLog 'sc start ZeroTierOneService'
SectionEnd

Section "Uninstall"
  SetShellVarContext all

  nsExec::ExecToLog 'sc stop ZeroTierOneService'
  nsExec::ExecToLog '"$INSTDIR\\zerotier-one_x64.exe" -R'

  Delete "$INSTDIR\\zerotier-one_x64.exe"
  Delete "$INSTDIR\\zerotier-cli.bat"
  Delete "$INSTDIR\\zerotier-idtool.bat"
  Delete "$INSTDIR\\Uninstall.exe"
  RMDir "$INSTDIR"

  Delete "$APPDATA\\ZeroTier\\One\\zttap300.inf"
  Delete "$APPDATA\\ZeroTier\\One\\zttap300.sys"
  Delete "$APPDATA\\ZeroTier\\One\\zttap300.cat"

  DeleteRegKey HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\ZeroTierOneCross"
SectionEnd
