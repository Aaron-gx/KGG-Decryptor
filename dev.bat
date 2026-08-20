@echo off
rem Launch music decryptor in dev mode (ASCII build path + custom Rust paths)
set CARGO_HOME=D:\Softwares\oa-tools\cargo-home
set RUSTUP_HOME=D:\Softwares\oa-tools\rustup-home
set PATH=D:\Softwares\oa-tools\oa-mingw\mingw64\bin;D:\Softwares\oa-tools\cargo-home\bin;%PATH%

set SRC=D:\Learn\IndivProject\2026.8.8¡¾music¡¿\tauri-app
set DST=D:\tmp\music-src
if not exist D:\tmp mkdir D:\tmp
robocopy "%SRC%" "%DST%" /MIR /XD target /NFL /NDL /NJH /NJS >nul
if errorlevel 8 (
  echo robocopy failed with errorlevel %errorlevel%
  exit /b 1
)
cd /d "%DST%"
npm run dev
