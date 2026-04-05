# ForensicSuite Icons

For production builds, place the following icon files here:

## Required Icons:
- `icon.ico` - Windows ICO format (256x256)
- `icon.icns` - macOS ICNS format (512x512)
- `32x32.png` - Windows small icon (32x32)
- `128x128.png` - Windows large icon (128x128)  
- `128x128@2x.png` - macOS Retina icon (256x256)

## Generating Icons:
You can use the `tauri icon` command to generate icons from a source image:
```bash
tauri icon /path/to/source.png
```

## Note:
Without icons, the build will still succeed but will use default Tauri icons.
