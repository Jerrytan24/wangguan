@echo off
echo Building NetMan...
go build -ldflags "-H windowsgui" -o netman.exe .
echo Build complete!
pause