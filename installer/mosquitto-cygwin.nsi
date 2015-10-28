; NSIS installer script for eecloud

!include "MUI.nsh"

; For environment variable code
!include "WinMessages.nsh"
!define env_hklm 'HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"'

Name "eecloud"
!define VERSION 1.4.2
OutFile "eecloud-${VERSION}-install-cygwin.exe"

InstallDir "$PROGRAMFILES\eecloud"

;--------------------------------
; Installer pages
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES

!define MUI_FINISHPAGE_TEXT "eecloud has been installed on your computer.\n\nTo complete the installation you must install the dependencies described in the following readme.\n\nClick Finish to close this wizard."
!define MUI_FINISHPAGE_SHOWREADME $INSTDIR\readme-dependencies-cygwin.txt
!define MUI_FINISHPAGE_SHOWREADME_TEXT "Show dependencies readme"
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
	;File "c:\cygwin\bin\cygwin1.dll"
	;File "c:\cygwin\bin\cyggcc_s-1.dll"
	;File "c:\cygwin\bin\cygcrypto-1.0.0.dll"
	;File "c:\cygwin\bin\cygssl-1.0.0.dll"
	;File "c:\cygwin\bin\cygz.dll"
	File "..\src\eecloud.exe"
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
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\EecloudCygwin" "DisplayName" "Eecloud MQTT broker"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\EecloudCygwin" "UninstallString" "$\"$INSTDIR\Uninstall.exe$\""
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\EecloudCygwin" "QuietUninstallString" "$\"$INSTDIR\Uninstall.exe$\" /S"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\EecloudCygwin" "HelpLink" "http://eecloud.org/"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\EecloudCygwin" "URLInfoAbout" "http://eecloud.org/"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\EecloudCygwin" "DisplayVersion" "${VERSION}"
	WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\EecloudCygwin" "NoModify" "1"
	WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\EecloudCygwin" "NoRepair" "1"

	WriteRegExpandStr ${env_hklm} EECLOUD_DIR $INSTDIR
	SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=5000
SectionEnd

Section "Service" SecService
	ExecWait '"$INSTDIR\eecloud.exe" install'
SectionEnd

Section "Uninstall"
	ExecWait '"$INSTDIR\eecloud.exe" uninstall'
	;Delete "$INSTDIR\cygwin1.dll"
	;Delete "$INSTDIR\cyggcc_s-1.dll"
	;Delete "$INSTDIR\cygcrypto-1.0.0.dll"
	;Delete "$INSTDIR\cygssl-1.0.0.dll"
	;Delete "$INSTDIR\cygz.dll"
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
	DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\EecloudCygwin"

	DeleteRegValue ${env_hklm} EECLOUD_DIR
	SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=5000
SectionEnd

LangString DESC_SecInstall ${LANG_ENGLISH} "The main installation."
LangString DESC_SecService ${LANG_ENGLISH} "Install eecloud as a Windows service (needs all dependencies installed)?"
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
	!insertmacro MUI_DESCRIPTION_TEXT ${SecInstall} $(DESC_SecInstall)
	!insertmacro MUI_DESCRIPTION_TEXT ${SecService} $(DESC_SecService)
!insertmacro MUI_FUNCTION_DESCRIPTION_END
