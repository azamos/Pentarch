@echo off
echo Building server...
g++ server/server.cpp third_party/sqlite/libsqlite3.a -lws2_32 -o build/server.exe

if %errorlevel% equ 0 (
    echo Build successful! Output: build/server.exe
    echo.
    echo Starting server...
    echo.
    build\server.exe
) else (
    echo Build failed with error code %errorlevel%
    echo.
    pause
)