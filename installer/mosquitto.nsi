; NSIS installer script for eecloud

!include "MUI2.nsh"
!include "nsDialogs.nsh"
!include "LogicLib.nsh"

; For environment variable code
!include "WinMessages.nsh"
!define env_hklm 'HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"'

Name "eecloud"
!define VERSION 1.4.2
OutFile "eecloud-${VERSION}-install-win32.exe"

InstallDir "$PROGRAMFILES\eecloud"

;--------------------------------
; Installer pages
!insertmacro MUI_PAGE_WELCOME

Page custom DependencyPage
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH


;--------------------------------
; Uninstaller pages
!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

;--------------------------------
; Languages
!insertmacro MUI_LANGUAGE "English"

;--------------------------------
; Installer sections

Section "Files" SecInstall
	SectionIn RO
	SetOutPath "$INSTDIR"
	File "..\build\src\Release\eecloud.exe"
	File "..\build\src\Release\eecloud_passwd.exe"
	File "..\build\client\Release\eecloud_pub.exe"
	File "..\build\client\Release\eecloud_sub.exe"
	File "..\build\lib\Release\eecloud.dll"
	File "..\build\lib\cpp\Release\eecloudpp.dll"
	File "..\aclfile.example"
	File "..\ChangeLog.txt"
	File "..\eecloud.conf"
	File "..\pwfile.example"
	File "..\readme.txt"
	File "..\readme-windows.txt"
	;File "C:\pthreads\Pre-built.2\dll\x86\pthreadVC2.dll"
	;File "C:\OpenSSL-Win32\libeay32.dll"
	;File "C:\OpenSSL-Win32\ssleay32.dll"
	File "..\edl-v10"
	File "..\epl-v10"

	SetOutPath "$INSTDIR\devel"
	File "..\lib\eecloud.h"
	File "..\build\lib\Release\eecloud.lib"
	File "..\lib\cpp\eecloudpp.h"
	File "..\build\lib\cpp\Release\eecloudpp.lib"
	File "..\src\eecloud_plugin.h"

	WriteUninstaller "$INSTDIR\Uninstall.exe"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Eecloud" "DisplayName" "Eecloud MQTT broker"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Eecloud" "UninstallString" "$\"$INSTDIR\Uninstall.exe$\""
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Eecloud" "QuietUninstallString" "$\"$INSTDIR\Uninstall.exe$\" /S"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Eecloud" "HelpLink" "http://eecloud.org/"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Eecloud" "URLInfoAbout" "http://eecloud.org/"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Eecloud" "DisplayVersion" "${VERSION}"
	WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Eecloud" "NoModify" "1"
	WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Eecloud" "NoRepair" "1"

	WriteRegExpandStr ${env_hklm} EECLOUD_DIR $INSTDIR
	SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=5000
SectionEnd

Section "Service" SecService
	ExecWait '"$INSTDIR\eecloud.exe" install'
SectionEnd

Section "Uninstall"
	ExecWait '"$INSTDIR\eecloud.exe" uninstall'
	Delete "$INSTDIR\eecloud.exe"
	Delete "$INSTDIR\eecloud_passwd.exe"
	Delete "$INSTDIR\eecloud_pub.exe"
	Delete "$INSTDIR\eecloud_sub.exe"
	Delete "$INSTDIR\eecloud.dll"
	Delete "$INSTDIR\eecloudpp.dll"
	Delete "$INSTDIR\aclfile.example"
	Delete "$INSTDIR\ChangeLog.txt"
	Delete "$INSTDIR\eecloud.conf"
	Delete "$INSTDIR\pwfile.example"
	Delete "$INSTDIR\readme.txt"
	Delete "$INSTDIR\readme-windows.txt"
	;Delete "$INSTDIR\pthreadVC2.dll"
	;Delete "$INSTDIR\libeay32.dll"
	;Delete "$INSTDIR\ssleay32.dll"
	Delete "$INSTDIR\edl-v10"
	Delete "$INSTDIR\epl-v10"

	Delete "$INSTDIR\devel\eecloud.h"
	Delete "$INSTDIR\devel\eecloud.lib"
	Delete "$INSTDIR\devel\eecloudpp.h"
	Delete "$INSTDIR\devel\eecloudpp.lib"
	Delete "$INSTDIR\devel\eecloud_plugin.h"

	Delete "$INSTDIR\Uninstall.exe"
	RMDir "$INSTDIR"
	DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Eecloud"

	DeleteRegValue ${env_hklm} EECLOUD_DIR
	SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=5000
SectionEnd

LangString DESC_SecInstall ${LANG_ENGLISH} "The main installation."
LangString DESC_SecService ${LANG_ENGLISH} "Install eecloud as a Windows service?"
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
	!insertmacro MUI_DESCRIPTION_TEXT ${SecInstall} $(DESC_SecInstall)
	!insertmacro MUI_DESCRIPTION_TEXT ${SecService} $(DESC_SecService)
!insertmacro MUI_FUNCTION_DESCRIPTION_END

Var Dialog
Var OSSLLink
Var PTHLink

Function DependencyPage
	nsDialogs::Create 1018
	Pop $Dialog

	${If} $Dialog == error
		Abort
	${EndIf}

	${NSD_CreateLabel} 0 0 100% 12u "OpenSSL - install 'Win32 OpenSSL vXXXXX Light' then copy dlls to the eecloud directory"
	${NSD_CreateLink} 13u 13u 100% 12u "http://slproweb.com/products/Win32OpenSSL.html"
	Pop $OSSLLink
	${NSD_OnClick} $OSSLLink OnClick_OSSL

	${NSD_CreateLabel} 0 26u 100% 12u "pthreads - copy 'pthreadVC2.dll' to the eecloud directory"
	${NSD_CreateLink} 13u 39u 100% 12u "ftp://sources.redhat.com/pub/pthreads-win32/dll-latest/dll/x86/"
	Pop $PTHLink
	${NSD_OnClick} $PTHLink OnClick_PTH

	!insertmacro MUI_HEADER_TEXT_PAGE "Dependencies" "This page lists packages that must be installed if not already present"
	nsDialogs::Show
FunctionEnd

Function OnClick_OSSL
	Pop $0
	ExecShell "open" "http://slproweb.com/products/Win32OpenSSL.html"
FunctionEnd

Function OnClick_PTH
	Pop $0
	ExecShell "open" "ftp://sources.redhat.com/pub/pthreads-win32/dll-latest/dll/x86/"
FunctionEnd
