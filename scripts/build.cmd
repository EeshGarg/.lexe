@echo off
rem Lexe one-shot Windows build (ARCHITECTURE.md #Build).
rem Usage: build.cmd [build-dir-name]   (default: build)
rem Configures + builds + runs ctest. Exits non-zero on any failure.
setlocal

set "BUILD_DIR=%~1"
if "%BUILD_DIR%"=="" set "BUILD_DIR=build"

set "REPO=%~dp0.."
set "VSROOT=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools"

call "%VSROOT%\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 exit /b 1

set "PATH=%VSROOT%\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin;%VSROOT%\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja;%PATH%"

cmake -S "%REPO%" -B "%REPO%\%BUILD_DIR%" -G Ninja -DCMAKE_BUILD_TYPE=Release
if errorlevel 1 exit /b 1

cmake --build "%REPO%\%BUILD_DIR%"
if errorlevel 1 exit /b 1

ctest --test-dir "%REPO%\%BUILD_DIR%" --output-on-failure
if errorlevel 1 exit /b 1

endlocal
exit /b 0
