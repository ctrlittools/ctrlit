@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

rem "build.bat ci" only compiles (used by the GitHub release workflow).
set "CI="
if /i "%~1"=="ci" set "CI=1"

set "FW=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319"
if not exist "%FW%\csc.exe" set "FW=%WINDIR%\Microsoft.NET\Framework\v4.0.30319"
if not exist "%FW%\csc.exe" (
  echo Could not find the .NET Framework 4 C# compiler.
  if not defined CI pause
  exit /b 1
)

if not defined CI (
  taskkill /im ctrlit.exe /f >nul 2>&1
  taskkill /im IPHover.exe /f >nul 2>&1
)

rem The icon is used for the .exe file and also built in for the tray.
set "ICON="
if exist ctrlit.ico set "ICON=/win32icon:ctrlit.ico /resource:ctrlit.ico,ctrlit.ico"

set BASE=/nologo /target:winexe /optimize+ /out:ctrlit.exe %ICON% /lib:"%FW%\WPF" /r:System.dll /r:System.Core.dll /r:System.Drawing.dll /r:System.Windows.Forms.dll /r:System.Xaml.dll /r:WindowsBase.dll /r:UIAutomationClient.dll /r:UIAutomationTypes.dll /r:UIAutomationProvider.dll

rem References for Windows' built-in text recognition (screen reading).
set "WINRT="
for %%f in ("%WINDIR%\System32\WinMetadata\*.winmd") do set WINRT=!WINRT! /r:"%%f"
for %%n in (System.Runtime.WindowsRuntime.dll System.Runtime.dll System.Runtime.InteropServices.WindowsRuntime.dll System.ObjectModel.dll System.Collections.dll System.Threading.Tasks.dll) do (
  if exist "%FW%\%%n" (
    set WINRT=!WINRT! /r:"%FW%\%%n"
  ) else if exist "%FW%\Facades\%%n" (
    set WINRT=!WINRT! /r:"%FW%\Facades\%%n"
  )
)

set "NOOCR="
echo === build with screen reading === > build.log
echo refs: !WINRT! >> build.log
"%FW%\csc.exe" %BASE% /define:OCR !WINRT! CtrlIt.cs >> build.log 2>&1
if errorlevel 1 (
  set "NOOCR=1"
  echo === that failed - build without screen reading === >> build.log
  "%FW%\csc.exe" %BASE% CtrlIt.cs >> build.log 2>&1
  if errorlevel 1 (
    type build.log
    echo.
    echo Build failed - the details are saved in build.log.
    if not defined CI pause
    exit /b 1
  )
)
echo === done === >> build.log

if defined CI (
  type build.log
  if defined NOOCR (
    echo ERROR: built WITHOUT screen reading - see build.log
    exit /b 2
  )
  exit /b 0
)

echo Built ctrlit.exe - starting it. Look for the blue Ctrl key icon in the system tray.
start "" "%~dp0ctrlit.exe"
if defined NOOCR (
  echo.
  echo NOTE: built WITHOUT screen reading - the details are saved in build.log.
  pause
) else (
  timeout /t 4 >nul
)
