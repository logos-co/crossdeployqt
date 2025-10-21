# Crossdeployqt

This is a tool that collects the dependencies and assets for a Qt 6 application so it is suitable for packaging & deployment.

It supports Linux, macOS & Windows(MingW) binaries, and can be viewed as an alternative for `windeployqt`, `macdeployqt` and `linuxdeployqt`.

Crossdeployqt is used on a Linux host, and can deploy for Linux & Windows(MingW). It could technically deploy macOS on a Linux host if you have the SDK & Qt frameworks, in our usage we use a macOS host.

Code signing, packaging & installers for distribution is out of scope, use dedicated packaging tools i.e [Velopack](https://velopack.io). For convienience, `vpk` and `velopack-libc` with MingW bindings, as well as `appimagetool` and its type2 runtimes via `appimagetool-full` are provided by the Nix derivation.


## Usage 

`$ crossdeployqt --bin <path-to-binary> --out <output-dir> [--qml-root <dir>]... [--languages <lang[,lang...>]> [--overlay <dir>]...`

i.e

```bash
$ crossdeployqt --bin <PATH TO>/foo.exe --out ./dist-win/
$ crossdeployqt --bin <PATH TO>/foo --out ./dist-linux/
$ crossdeployqt --bin <PATH TO>/foo.app/Contents/MacOS/bar --out ./dist-macos/
```


Under Nix `crossdeployqt` is wrapped with all tools required for operation on PATH: `qtpaths`, `qmlimportscanner`, `lconvert`, `objdump`, `patchelf`, `x86_64-w64-mingw32-objdump`, `llvm-otool`, `llvm-install-name-tool`, and `find`.

`$ nix run github:logos-co/crossdeployqt -- --help` 

or 

```nix
{
  inputs.crossdeployqt.url = "github:logos-co/crossdeployqt";
  outputs = { self, nixpkgs, crossdeployqt, ... }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
    in {
      devShells.${system}.default = pkgs.mkShell {
        packages = [ crossdeployqt.packages.${system}.default ];
      };
    };
}
```
## Packaging

Velopack can be used for packaging & code-signing on multiple platforms, requires no `appimagetool` and does not require using their updater functionality using `--skipVeloAppCheck`.


### Windows

Velopack signs every PE binary it finds under `--packDir` — i.e., .exe and .dll — recursively by default. You can switch to "EXE‑only" with `--signSkipDll`, and you can exclude files with a regex via 
`--signExclude "\.(resources|dbg)\.dll$"`.

You may want to look into `--signParams ...`, `--azureTrustedSignFile`, `--signParallel` as needed.

```powershell
vpk pack ^
  --packId com.example.myapp ^
  --packVersion 1.0.0 ^
  --packDir dist\win-x64 ^
  --mainExe MyApp.exe ^
  --packTitle "My App" ^
  --icon build\myapp.ico ^
  --delta none ^
  --noPortable ^
  --signParams "/a /fd sha256 /tr http://timestamp.digicert.com /td sha256" ^
  --skipVeloAppCheck
```

### macOS

By default Velopack codesigns the entire .app bundle ("deep signing") and then notarizes, which covers frameworks/dylibs. With `--signDisableDeep` Velopack expects the bundle to be pre‑signed.

Notarisation requires `notarytool` on your PATH.

`--signAppIdentity`, `--signInstallIdentity`, `--notaryProfile`

```bash
vpk pack \
  --packId com.example.myapp \
  --packVersion 1.0.0 \
  --packDir dist/MyApp.app \
  --mainExe MyApp \
  --packTitle "My App" \
  --icon build/myapp.icns \
  --delta none \
  --noPortable \
  --signAppIdentity "Developer ID Application: Your Company (TEAMID)" \
  --signInstallIdentity "Developer ID Installer: Your Company (TEAMID)" \
  --notaryProfile "MyNotaryProfile"
```

### Linux AppImage

For Linux, there isn't an OS‑level code‑signing pass for ELF binaries

```bash
vpk pack \
  --packId com.example.myapp \
  --packVersion 1.0.0 \
  --packDir dist/linux-x64 \
  --mainExe myapp \
  --packTitle "My App"
```

## Notes

Missing features:
- [ ] Automatic translation file handling
- [ ] No Wayland detection, XCB is assumed on Linux
- [ ] Missing types (tls, styles, iconengines, sqldrivers, multimedia, printsupport, platformthemes, etc.)