# Crossdeployqt

This is a tool that collects the dependencies and assets for a Qt 6 application so it is suitable for packaging & deployment.

It supports Linux, macOS & Windows(MingW) binaries, and can be viewed as an alternative for `windeployqt`, `macdeployqt` and `linuxdeployqt`.

Crossdeployqt is used on a Linux host, and can deploy for Linux & Windows(MingW). It could technically deploy macOS on a Linux host if you have the SDK & Qt frameworks, in our usage we use a macOS host.

Code signing, packaging & installers for distribution is out of scope, use dedicated packaging tools i.e [Velopack](https://velopack.io).


## Usage 

`$ crossdeployqt --bin <path-to-binary> --out <output-dir> [--qml-root <dir>]... [--languages <lang[,lang...>]> [--overlay <dir>]...`

i.e

```bash
$ crossdeployqt --bin <PATH TO>/foo.exe --out ./dist-win/
$ crossdeployqt --bin <PATH TO>/foo --out ./dist-linux/
$ crossdeployqt --bin <PATH TO>/foo.app/Contents/MacOS/bar --out ./dist-macos/
```


Under Nix `crossdeployqt` is wrapped with all tools required for operation on PATH: `qtpaths`, `qmlimportscanner`, `lconvert`, `objdump`, `patchelf`, `x86_64-w64-mingw32-objdump`, `llvm-otool`, `llvm-install-name-tool`, and `find`.

`$ nix run github:logos-co/crossdeployqt` 

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

Missing features:
- [ ] Automatic translation file handling
- [ ] No Wayland detection, XCB is assumed on Linux
- [ ] Missing types (tls, styles, iconengines, sqldrivers, multimedia, printsupport, platformthemes, etc.)