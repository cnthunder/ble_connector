# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['d:\\ble_connector\\ble_connector.py'],
    pathex=[],
    binaries=[],
    datas=[('d:\\ble_connector\\.venv\\Scripts\\ble-scan.exe', '.'), ('d:\\ble_connector\\.venv\\Scripts\\ble-serial.exe', '.'), ('d:\\ble_connector\\conf.json', '.')],
    hiddenimports=['PyQt5.QtCore', 'PyQt5.QtGui', 'PyQt5.QtWidgets', 'psutil'],
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
    [],
    exclude_binaries=True,
    name='BLEConnector',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='BLEConnector',
)
