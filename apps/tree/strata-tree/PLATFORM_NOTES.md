# Strata Tree — Platform Notes

## Supported Platforms

| Platform | Status | Notes |
|---|---|---|
| Windows 10/11 x64 | **Primary** | Full feature support including VSS enumeration |
| Windows PE/FE x64 | **Supported** | egui/glow works; no WinRT, no shell UI dependencies |
| Windows 7/8/8.1 x64 | **Best-effort** | Tested; some OpenGL drivers may be outdated |
| Ubuntu 22.04 x64 | **Supported** | Requires X11 or Wayland + OpenGL |
| macOS 13+ x64 | **Supported** | Metal backend via eframe/glow |
| macOS Apple Silicon (arm64) | **Untested** | Should work via cross-compile; not CI-validated |

---

## Windows PE / Forensic Environment

Strata Tree is designed to run inside Windows PE and Windows Forensic Environment (WinFE):

- **No installer required** — single portable `.exe` binary.
- **No .NET, no VC++ redistributables** — all Rust code, statically linked.
- **No shell extension registration** — does not call `SHGetKnownFolderPath` or similar.
- **No telemetry** — zero outbound network connections.
- **SQLite bundled** — rusqlite with `features = ["bundled"]`; no external DLL.
- **egui/glow** — uses OpenGL 3.3 via the `glow` backend. PE environments with adequate GPU drivers (even software rasterisers like llvmpipe) work correctly.

### Required in PE environment

- A GPU driver or software renderer with OpenGL 3.3+ support.
- Sufficient free memory for the evidence index (~50 MB base + ~1 MB per 10k files).
- A screen resolution of at least 1024×768 (1400×900 recommended).

### Volume Shadow Copy in PE

VSS enumeration uses `vssadmin list shadows` and direct device path probing (`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN\`). Administrator privileges are required for raw shadow copy access in PE. Launch `strata-tree.exe` from an elevated command prompt.

---

## Linux

Install dependencies (Debian/Ubuntu):

```sh
sudo apt-get install -y \
  libssl-dev \
  libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev \
  libxkbcommon-dev \
  libgl1-mesa-dev \
  libgtk-3-dev
```

Headless environments: use a virtual framebuffer (`Xvfb`) if no display is available.

---

## macOS

No extra dependencies beyond the standard Xcode command-line tools. The app links against system `libz` and OpenGL via eframe.

---

## Building from Source

```sh
# Clone the Strata monorepo
git clone https://github.com/strata-forensics/strata
cd strata

# Build Strata Tree in release mode
cargo build -p strata-tree --release

# Binary output
# Windows: target/release/strata-tree.exe
# Linux/macOS: target/release/strata-tree
```

### Cross-compilation (Linux → Windows)

```sh
# Install the MSVC target
rustup target add x86_64-pc-windows-msvc

# Requires cargo-xwin or a Windows SDK sysroot
cargo xwin build -p strata-tree --release --target x86_64-pc-windows-msvc
```

---

## Known Limitations

| Limitation | Workaround |
|---|---|
| VSS enumeration requires Administrator on Windows | Run `strata-tree.exe` as Administrator |
| Raw disk images (E01/AFF) require strata-fs with libewf | Build with `features = ["ewf"]` |
| macOS arm64 not CI-validated | Use Rosetta 2 or build natively |
| Gallery thumbnails for very large images (>100 MB) may be slow | Thumbnails are capped at 128×128; only the first 10 MB is decoded |
