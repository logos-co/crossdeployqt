{ pkgs }:

let
  inherit (pkgs) stdenv lib cmake pkg-config fetchFromGitHub fetchurl;

  # ---- Vendored type2-runtime binaries (pinned) ----
  # Release: "continuous" (commit 61e6688… on 2025‑08‑11).
  # Source: https://github.com/AppImage/type2-runtime/releases
  # Hashes are SRI (base64) derived from release page sha256 values.
  type2Runtime = rec {
    version = "continuous-20250811-61e6688";
    x86_64 = fetchurl {
      url = "https://github.com/AppImage/type2-runtime/releases/download/continuous/runtime-x86_64";
      hash = "sha256-+SYBTW04kUyIHtx8i8roXsMQEbVF5Qsh2xu2vbcbTvE=";
      executable = true;
    };

    aarch64 = fetchurl {
      url = "https://github.com/AppImage/type2-runtime/releases/download/continuous/runtime-aarch64";
      hash = "sha256-3D5A4r3a4epuDt9TLA2HkAdUTquklOWvkIdbsmoZfuo=";
      executable = true;
    };

    # Helpful for cross-targeting from x86_64/aarch64 hosts
    i686 = fetchurl {
      url = "https://github.com/AppImage/type2-runtime/releases/download/continuous/runtime-i686";
      hash = "sha256-6m6md7XIpFlu8Gs0ohPD4xXLeibIyYgPrzU9LQbr54k=";
      executable = true;
    };
    
    armhf = fetchurl {
      url = "https://github.com/AppImage/type2-runtime/releases/download/continuous/runtime-armhf";
      hash = "sha256-a6FYj1PBNjDcTU31AzWpGz0vRZqbWDRi6OmPaBuBLWQ=";
      executable = true;
    };

    drv = stdenv.mkDerivation {
      pname = "type2-runtimes";
      inherit version;
      dontUnpack = true;
      installPhase = ''
        mkdir -p $out/share/appimage/type2-runtime
        cp -v ${x86_64}  $out/share/appimage/type2-runtime/runtime-x86_64
        cp -v ${aarch64} $out/share/appimage/type2-runtime/runtime-aarch64
        cp -v ${i686}    $out/share/appimage/type2-runtime/runtime-i686
        cp -v ${armhf}   $out/share/appimage/type2-runtime/runtime-armhf
        chmod +x $out/share/appimage/type2-runtime/*
      '';
      meta = with lib; {
        description = "Pinned AppImage type-2 runtimes for multiple architectures";
        homepage    = "https://github.com/AppImage/type2-runtime/releases";
        license     = licenses.gpl2Plus;
        platforms   = platforms.linux;
      };
    };
  };

in rec {

  appimagetool = stdenv.mkDerivation rec {
    pname = "appimagetool";
    version = "continuous-2025-10-13-aa0b7dc";

    src = fetchFromGitHub {
      owner = "AppImage";
      repo  = "appimagetool";
      rev   = "aa0b7dcd6abdd127b11a540c848dd230ebcc5d8b";
      hash  = "sha256-/QpTa1BPQ/DpDclkrwYEJZoYaEAyDiXBwr1SgGOiZKw=";
      fetchSubmodules = false;
    };

    nativeBuildInputs = [
      cmake
      pkg-config
    ];

    # Upstream CMake checks for these via pkg-config
    buildInputs = with pkgs; [
      glib            # glib-2.0 + gio-2.0
      gpgme
      libgcrypt
      libgpg-error
      curl            # libcurl
    ];

    # External tools invoked by appimagetool
    runtimeTools = with pkgs; [
      squashfsTools   # mksquashfs
      zsync           # zsyncmake (optional but common)
      gnupg           # gpg for signing via gpgme
      desktop-file-utils # desktop-file-validate
      file            # helps when debugging / inspecting binaries
      patchelf        # occasionally useful for fixing RPATH in AppDirs
    ];

    cmakeFlags = [
      "-DBUILD_STATIC=OFF"
    ];

    postInstall = ''
      # Move the real binary aside
      mkdir -p $out/libexec
      mv -v $out/bin/appimagetool $out/libexec/appimagetool-real

      # Smart wrapper:
      # - Adds --runtime-file unless user already provided one
      # - Chooses runtime by $ARCH (or defaults to host arch)
      # - Exposes required CLI tools on PATH
      cat > $out/bin/appimagetool <<'EOF'
      #!${pkgs.bash}/bin/bash
      set -euo pipefail

      # If caller already set a runtime, do not interfere
      have_runtime=0
      for arg in "$@"; do
        case "$arg" in
          --runtime-file|--runtime-file=*) have_runtime=1; break ;;
        esac
      done

      # Construct PATH for helper tools
      export PATH="${lib.makeBinPath runtimeTools}:$PATH"

      # Ensure TLS works if something ever hits HTTPS (e.g., user-supplied URLs)
      export SSL_CERT_FILE="${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"

      if [[ $have_runtime -eq 0 ]]; then
        # Resolve target arch
        target="${ARCH:-}"
        if [[ -z "$target" ]]; then
          # Default to host arch if ARCH not provided
          case "${stdenv.hostPlatform.system}" in
            x86_64-*) target=x86_64 ;;
            aarch64-*) target=aarch64 ;;
            i686-*) target=i686 ;;
            armv7l-*) target=armhf ;;
            *) target=x86_64 ;;
          esac
        fi

        # Normalize common synonyms
        case "$target" in
          amd64|x86-64) target=x86_64 ;;
          arm64)        target=aarch64 ;;
          i386)         target=i686 ;;
          arm|armv7*)   target=armhf ;;
        esac

        case "$target" in
          x86_64) runtime="${type2Runtime.drv}/share/appimage/type2-runtime/runtime-x86_64" ;;
          aarch64) runtime="${type2Runtime.drv}/share/appimage/type2-runtime/runtime-aarch64" ;;
          i686) runtime="${type2Runtime.drv}/share/appimage/type2-runtime/runtime-i686" ;;
          armhf) runtime="${type2Runtime.drv}/share/appimage/type2-runtime/runtime-armhf" ;;
          *)
            echo "appimagetool wrapper: unsupported ARCH '$target'." >&2
            echo "Supported: x86_64, aarch64, i686, armhf (set ARCH=… or pass --runtime-file)." >&2
            exit 2
            ;;
        esac

        exec -a "$0" "$out/libexec/appimagetool-real" --runtime-file "$runtime" "$@"
      else
        exec -a "$0" "$out/libexec/appimagetool-real" "$@"
      fi
      EOF
      chmod +x $out/bin/appimagetool
    '';

    meta = with lib; {
      description = "Low-level tool to generate an AppImage from an existing AppDir";
      homepage    = "https://github.com/AppImage/appimagetool";
      license     = licenses.mit;
      platforms   = platforms.linux;
      mainProgram = "appimagetool";
    };
  };

  appimagetool-full = pkgs.symlinkJoin {
    name = "appimagetool-full";
    paths = [ appimagetool type2Runtime.drv ];
  };
}