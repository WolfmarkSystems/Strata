# Strata Tree Windows Installer

This directory contains NSIS installer assets for `strata-tree.exe`.

## Files

- `strata-tree.nsi` - NSIS installer definition
- `build-installer.ps1` - helper script to compile release and run `makensis`

## Requirements

- NSIS installed and `makensis.exe` available in `PATH`
- Rust toolchain available in `PATH`

## Build

```powershell
cd D:\Strata\apps\tree\strata-tree\installer
.\build-installer.ps1
```

The installer output is:

- `strata-tree-setup-1.0.0.exe`

## Installer behavior

- Installs to `%ProgramFiles%\Strata\Tree\`
- Creates Start Menu and Desktop shortcuts
- Registers `.vtp` file association
- Installs an uninstaller entry
