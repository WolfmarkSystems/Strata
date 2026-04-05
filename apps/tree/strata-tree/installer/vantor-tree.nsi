; Vantor Tree NSIS installer script.
; Builds a per-machine installer with .vtp file association.

!include "MUI2.nsh"
!include "FileFunc.nsh"

!define APP_NAME "Vantor Tree"
!define APP_VERSION "1.0.0"
!define APP_PUBLISHER "Vantor"
!define APP_EXE "vantor-tree.exe"
!define INSTALL_DIR "$PROGRAMFILES64\\Vantor\\Tree"
!define STARTMENU_DIR "$SMPROGRAMS\\Vantor"
!define UNINSTALL_KEY "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\VantorTree"

Name "${APP_NAME} ${APP_VERSION}"
OutFile "vantor-tree-setup-${APP_VERSION}.exe"
InstallDir "${INSTALL_DIR}"
InstallDirRegKey HKLM "Software\\Vantor\\Tree" "InstallDir"
RequestExecutionLevel admin

!define MUI_ABORTWARNING
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Section "Install"
  SetShellVarContext all
  SetOutPath "$INSTDIR"

  File "..\\..\\..\\..\\target\\release\\${APP_EXE}"
  IfFileExists "$INSTDIR\\${APP_EXE}" +2 0
    MessageBox MB_ICONSTOP "Failed to install ${APP_EXE}"

  ; Registry keys for uninstall entry.
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayName" "${APP_NAME} ${APP_VERSION}"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "Publisher" "${APP_PUBLISHER}"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayVersion" "${APP_VERSION}"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "UninstallString" "$INSTDIR\\Uninstall.exe"
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "NoRepair" 1
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  IntFmt $0 "0x%08X" $0
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "EstimatedSize" "$0"

  ; Store install dir.
  WriteRegStr HKLM "Software\\Vantor\\Tree" "InstallDir" "$INSTDIR"

  ; .vtp file association.
  WriteRegStr HKCR ".vtp" "" "VantorTree.Case"
  WriteRegStr HKCR "VantorTree.Case" "" "Vantor Tree Case File"
  WriteRegStr HKCR "VantorTree.Case\\DefaultIcon" "" "$INSTDIR\\${APP_EXE},0"
  WriteRegStr HKCR "VantorTree.Case\\shell\\open\\command" "" '"$INSTDIR\\${APP_EXE}" "%1"'

  ; Start menu shortcut.
  CreateDirectory "${STARTMENU_DIR}"
  CreateShortCut "${STARTMENU_DIR}\\Vantor Tree.lnk" "$INSTDIR\\${APP_EXE}"
  CreateShortCut "$DESKTOP\\Vantor Tree.lnk" "$INSTDIR\\${APP_EXE}"

  ; Uninstaller.
  WriteUninstaller "$INSTDIR\\Uninstall.exe"
SectionEnd

Section "Uninstall"
  SetShellVarContext all
  Delete "$INSTDIR\\${APP_EXE}"
  Delete "$INSTDIR\\Uninstall.exe"

  Delete "${STARTMENU_DIR}\\Vantor Tree.lnk"
  RMDir "${STARTMENU_DIR}"
  Delete "$DESKTOP\\Vantor Tree.lnk"

  DeleteRegKey HKLM "${UNINSTALL_KEY}"
  DeleteRegKey HKLM "Software\\Vantor\\Tree"
  DeleteRegKey HKCR "VantorTree.Case\\shell\\open\\command"
  DeleteRegKey HKCR "VantorTree.Case\\DefaultIcon"
  DeleteRegKey HKCR "VantorTree.Case"
  DeleteRegValue HKCR ".vtp" ""

  RMDir "$INSTDIR"
SectionEnd
