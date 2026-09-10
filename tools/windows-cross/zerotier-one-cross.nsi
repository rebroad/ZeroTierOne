Unicode false
RequestExecutionLevel admin
InstallDir "$PROGRAMFILES64\\ZeroTier\\One"
!ifdef OUTPUT_FILE
OutFile "${OUTPUT_FILE}"
!else
OutFile "ZeroTier-One-x64-Installer.exe"
!endif
Name "ZeroTier One (x64)"
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
  nsExec::ExecToLog 'cmd /c "echo [ZeroTier Installer] Starting install > \"C:\\Temp\\ZeroTier-One-install.log\""'

  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP "This installer requires 64-bit Windows."
    Abort
  ${EndIf}

  nsExec::ExecToLog 'cmd /c "echo [1/4] Installing files >> \"C:\\Temp\\ZeroTier-One-install.log\""'
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

  nsExec::ExecToLog 'cmd /c "echo [2/4] Registering uninstaller and metadata >> \"C:\\Temp\\ZeroTier-One-install.log\""'
  WriteUninstaller "$INSTDIR\\Uninstall.exe"

  WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\ZeroTierOne" "DisplayName" "ZeroTier One (x64)"
  WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\ZeroTierOne" "UninstallString" "$INSTDIR\\Uninstall.exe"
  WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\ZeroTierOne" "InstallLocation" "$INSTDIR"
  WriteRegDWORD HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\ZeroTierOne" "NoModify" 1
  WriteRegDWORD HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\ZeroTierOne" "NoRepair" 1

  nsExec::ExecToLog 'cmd /c "echo [3/4] Reinstalling ZeroTier service (update-safe) >> \"C:\\Temp\\ZeroTier-One-install.log\""'
  nsExec::ExecToLog 'sc stop ZeroTierOneService'
  nsExec::ExecToLog '"$INSTDIR\\zerotier-one_x64.exe" -R'
  nsExec::ExecToLog '"$INSTDIR\\zerotier-one_x64.exe" -I'
  Pop $0
  ${If} $0 != 0
    nsExec::ExecToLog 'cmd /c "echo [ERROR] Service install failed with code $0 >> \"C:\\Temp\\ZeroTier-One-install.log\""'
    MessageBox MB_ICONSTOP "Service installation failed (exit code $0)."
    Abort
  ${EndIf}

  nsExec::ExecToLog 'cmd /c "echo [4/4] Starting ZeroTier service >> \"C:\\Temp\\ZeroTier-One-install.log\""'
  nsExec::ExecToLog 'sc start ZeroTierOneService'
  nsExec::ExecToLog 'cmd /c "echo [DONE] Install complete >> \"C:\\Temp\\ZeroTier-One-install.log\""'
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

  DeleteRegKey HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\ZeroTierOne"
SectionEnd
