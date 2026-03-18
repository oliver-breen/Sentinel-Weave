# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_submodules

hiddenimports = ['pkgutil', 'pqcrypto', 'quantaweave', 'secrets']
hiddenimports += collect_submodules('secrets')


a = Analysis(
    ['gui\\quantaweave_gui.py'],
    pathex=[],
    binaries=[],
    datas=[('pqcrypto', 'pqcrypto'), ('quantaweave', 'quantaweave'), ('C:/Users/obree/anaconda3/Lib/site-packages/PyQt6/Qt6/plugins/platforms', 'PyQt6/Qt6/plugins/platforms')],
    hiddenimports=hiddenimports,
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
    name='quantaweave_gui',
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
)
