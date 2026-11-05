<# :
@echo off
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-Expression ([System.IO.File]::ReadAllText('%~f0'))"
exit /b %ERRORLEVEL%
#>
$ErrorActionPreference = 'Stop'
$msvc = 'C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231'
$sdkInc = 'C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0'
$sdkLib = 'C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0'
$sdkBin = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0'
$out = 'build'
$cl = "$msvc\bin\Hostx64\x64\cl.exe"
$link = "$msvc\bin\Hostx64\x64\link.exe"
New-Item -ItemType Directory -Force -Path "$out\int" | Out-Null
$exe = "$out\botox.exe"
$stampPath = "$out\int\build_fast.stamp"
$stamp = "v3|x64|$msvc|$sdkInc|$sdkLib"
$sources = @('src\main.cpp','src\imgui\imgui.cpp','src\imgui\imgui_draw.cpp','src\imgui\imgui_tables.cpp','src\imgui\imgui_widgets.cpp','src\imgui\imgui_impl_dx11.cpp','src\imgui\imgui_impl_win32.cpp','src\imgui\imgui_freetype.cpp')
$imguiHeaders = @(Get-ChildItem -LiteralPath 'src\imgui' -Filter '*.h' | ForEach-Object { $_.FullName })
$mainDeps = @('src\main.cpp','src\core\manualmap.h','src\core\release.h','src\core\icon_font.hpp','src\core\github_icon.hpp') + $imguiHeaders
$force = !(Test-Path $stampPath) -or ((Get-Content $stampPath -Raw).Trim() -ne $stamp)
function Needs-Build($obj, $deps) {
    if (!(Test-Path $obj)) { return $true }
    $t = (Get-Item $obj).LastWriteTimeUtc
    foreach ($d in $deps) { if ((Get-Item $d).LastWriteTimeUtc -gt $t) { return $true } }
    return $false
}
$changed = @()
foreach ($s in $sources) {
    $obj = "$out\int\$([System.IO.Path]::GetFileNameWithoutExtension($s)).obj"
    $deps = if ($s -like '*main.cpp') { $mainDeps } else { @($s) + $imguiHeaders }
    if ($force -or (Needs-Build $obj $deps)) { $changed += $s }
}
if ($changed.Count -gt 0) {
    $clArgs = @('/nologo','/c','/MP','/EHsc','/std:c++20','/O2','/Zc:inline','/utf-8','/Gy','/GF','/DNDEBUG','/D_WINDOWS','/D_UNICODE','/DUNICODE','/Isrc','/Isrc\core','/Isrc\imgui','/Isrc\freetype\include',"/I$msvc\include","/I$msvc\atlmfc\include","/I$sdkInc\ucrt","/I$sdkInc\um","/I$sdkInc\shared","/Fo$out\int\") + $changed
    & $cl @clArgs
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    Set-Content $stampPath -Value $stamp -NoNewline
}
$res = "$out\int\loader.res"
if ($force -or (Needs-Build $res @('src\loader.rc','src\icon.ico'))) {
    & "$sdkBin\x64\rc.exe" /nologo /fo $res src\loader.rc
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
$objects = @($sources | ForEach-Object { "$out\int\$([System.IO.Path]::GetFileNameWithoutExtension($_)).obj" }) + $res
$needLink = ($changed.Count -gt 0) -or (Needs-Build $exe $objects)
if ($needLink) {
    $linkArgs = @('/nologo','/SUBSYSTEM:WINDOWS','/MACHINE:X64','/MANIFEST:NO','/INCREMENTAL:NO','/OPT:REF','/OPT:ICF',"/OUT:$exe","/LIBPATH:$msvc\lib\x64","/LIBPATH:$sdkLib\ucrt\x64","/LIBPATH:$sdkLib\um\x64",'d3d11.lib','dxgi.lib','d3dcompiler.lib','winmm.lib','user32.lib','gdi32.lib','wininet.lib','shell32.lib','advapi32.lib','src\freetype\lib\freetype.lib') + $objects
    & $link @linkArgs
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
