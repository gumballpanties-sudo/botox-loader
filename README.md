# botox loader

auto updating dll loader for botox

based off [0zdac/botoxloader](https://github.com/0zdac/botoxloader)

![preview](https://i.imgur.com/dzOAKcc.png)

## targets

| target | repo | game |
|---|---|---|
| botox | [gumballpanties-sudo/botox](https://github.com/gumballpanties-sudo/botox) | cs:go legacy (`csgo.exe`) |
| botox tf2 | [gumballpanties-sudo/botox-tf2](https://github.com/gumballpanties-sudo/botox-tf2) | tf2 (`tf_win64.exe`) |

## what it does

- pulls `botox.dll` from the target repo's latest github release, sha256 checked
- caches in `%APPDATA%\botox\bin\` (tf2 in `bin\tf2\`), only redownloads when release changes
- waits up to 3 min for you to start the game, then for it to finish loading, then injects
  - csgo: manual map, LoadLibrary fallback
  - tf2: LoadLibrary
- settings (cog): accent color + dpi scale, saved to `%APPDATA%\botox\loader.cfg`

## build

needs visual studio 2022 (v143, "desktop development with c++") + windows 10/11 sdk. x64 only.

**visual studio:** open `loader.sln`, pick `Release | x64`, build.
output: `x64\Release\loader.exe`

**build.bat:** fast incremental build without msbuild.

```cmd
cd botox-loader
build.bat
```

output: `build\botox.exe`

`build.bat` hardcodes msvc + sdk paths at top (`$msvc`, `$sdkInc`, `$sdkLib`). edit them to match your install, e.g. vs 2022 community:

```powershell
$msvc   = 'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\<version>'
$sdkInc = 'C:\Program Files (x86)\Windows Kits\10\Include\<sdk version>'
$sdkLib = 'C:\Program Files (x86)\Windows Kits\10\Lib\<sdk version>'
```

freetype is prebuilt static (`src/freetype/lib/freetype.lib`, x64 /MT), nothing to install.
