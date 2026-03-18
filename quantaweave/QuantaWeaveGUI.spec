# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['gui\\quantaweave_gui.py'],
    pathex=[],
    binaries=[],
    datas=[('C:/Users/obree/anaconda3/Lib/site-packages/PyQt6/Qt6/plugins', 'PyQt6/Qt6/plugins'), ('C:/Users/obree/anaconda3/Lib/site-packages/PyQt6/Qt6/bin', 'PyQt6/Qt6/bin')],
    hiddenimports=['pkgutil'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='QuantaWeaveGUI',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['assets\\quantaweave.ico'],
)
