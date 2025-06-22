@echo off
echo Building server...

REM Set libsodium paths
set LIBSODIUM_PATH=third_party\libsodium-win64
set LIBSODIUM_INCLUDE=%LIBSODIUM_PATH%\include
set LIBSODIUM_LIB=%LIBSODIUM_PATH%\lib

g++ server/server.cpp ^
    -I%LIBSODIUM_INCLUDE% ^
    third_party\sqlite\libsqlite3.a ^
    -L%LIBSODIUM_LIB% -lsodium ^
    -lws2_32 ^
    -o build\server.exe

if %errorlevel% equ 0 (
    echo Build successful! Output: build\server.exe
    echo.
    echo Starting server...
    echo.
    build\server.exe
) else (
    echo Build failed with error code %errorlevel%
    echo.
    pause
)
