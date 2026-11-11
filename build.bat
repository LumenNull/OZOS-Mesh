@echo off
setlocal

echo =================================================================
echo   O.Z.O.S // SOVEREIGN MESH P2P BUILD SYSTEM (v1.3.0-MESH)
echo   Target: ozos-mesh.exe + test_security_hardening.exe (Zero-Heap)
echo =================================================================

where cl >nul 2>nul
if %ERRORLEVEL% EQU 0 goto :build_msvc

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%VSWHERE%" (
    for /f "usebackq delims=" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
        if exist "%%I\VC\Auxiliary\Build\vcvars64.bat" (
            echo [TOOLCHAIN] Activating Visual Studio C/C++ x64 Environment...
            call "%%I\VC\Auxiliary\Build\vcvars64.bat" >nul
            goto :build_msvc
        )
    )
)

where gcc >nul 2>nul
if %ERRORLEVEL% EQU 0 goto :build_gcc

where clang >nul 2>nul
if %ERRORLEVEL% EQU 0 goto :build_clang

echo [ERROR] No C compiler (MSVC cl, GCC, or Clang) found in PATH.
exit /b 1

:build_msvc
echo [COMPILER] Building with Microsoft Visual C++ (MSVC x64 /O2)...
cl /nologo /O2 /W4 /Iinclude src\main.c src\tweetnacl.c /Fe:ozos-mesh.exe advapi32.lib winmm.lib
if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%
cl /nologo /O2 /W4 /Iinclude tests\test_security_hardening.c src\tweetnacl.c /Fe:test_security_hardening.exe advapi32.lib winmm.lib
if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%
del /q *.obj >nul 2>nul
goto :done

:build_gcc
echo [COMPILER] Building with GNU GCC (-std=c99 -O3)...
gcc -std=c99 -O3 -Iinclude -c src/tweetnacl.c -o tweetnacl.o
if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%
gcc -std=c99 -O3 -Wall -Wextra -Werror -Iinclude src/main.c tweetnacl.o -o ozos-mesh.exe -ladvapi32 -lwinmm -lm
if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%
gcc -std=c99 -O3 -Wall -Wextra -Werror -Iinclude tests/test_security_hardening.c tweetnacl.o -o test_security_hardening.exe -ladvapi32 -lwinmm -lm
if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%
del /q tweetnacl.o >nul 2>nul
goto :done

:build_clang
echo [COMPILER] Building with LLVM Clang (-std=c99 -O3)...
clang -std=c99 -O3 -Iinclude -c src/tweetnacl.c -o tweetnacl.o
if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%
clang -std=c99 -O3 -Wall -Wextra -Werror -Iinclude src/main.c tweetnacl.o -o ozos-mesh.exe -ladvapi32 -lwinmm -lm
if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%
clang -std=c99 -O3 -Wall -Wextra -Werror -Iinclude tests/test_security_hardening.c tweetnacl.o -o test_security_hardening.exe -ladvapi32 -lwinmm -lm
if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%
del /q tweetnacl.o >nul 2>nul
goto :done

:done
echo [SUCCESS] Built ozos-mesh.exe and test_security_hardening.exe successfully.
exit /b 0
