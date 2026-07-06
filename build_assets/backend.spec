# -*- mode: python ; coding: utf-8 -*-

import os
from PyInstaller.utils.hooks import collect_submodules, collect_all

# Get the project root directory (parent of build_assets)
spec_root = os.path.abspath(SPECPATH)
project_root = os.path.dirname(spec_root)

block_cipher = None

# app.analyzer.report_generator was observed to be silently dropped from a
# frozen Windows build even with an explicit hiddenimport entry for it and
# no warning logged. collect_submodules() walks the actual package on disk
# (pkgutil.walk_packages) instead of relying on modulegraph's static
# analysis, which is more reliable for whatever this was. Applied to all
# three app subpackages as insurance - keep in sync with build_eel.bat and
# .github/workflows/build.yml.
app_submodules = (
    collect_submodules('app.analyzer')
    + collect_submodules('app.core')
    + collect_submodules('app.sandbox')
)

# Selenium's webdriver classes (selenium.webdriver.chrome.webdriver etc.)
# aren't caught by modulegraph's static analysis either - a frozen build
# crashed at runtime with "No module named
# selenium.webdriver.chrome.webdriver" despite being imported directly.
# collect_all() is the blanket fix (submodules + data + binaries).
selenium_datas, selenium_binaries, selenium_hidden = collect_all('selenium')
wdm_datas, wdm_binaries, wdm_hidden = collect_all('webdriver_manager')

a = Analysis(
    [os.path.join(project_root, 'app', 'eel_main.py')],
    pathex=[project_root],
    binaries=selenium_binaries + wdm_binaries,
    datas=[
        (os.path.join(project_root, 'app', 'static'), 'app/static'),
        (os.path.join(project_root, 'app', 'core', 'scoring_rules.yaml'), 'app/core'),
    ] + selenium_datas + wdm_datas,
    hiddenimports=app_submodules + selenium_hidden + wdm_hidden + [
        'uvicorn.logging',
        'uvicorn.loops',
        'uvicorn.loops.auto',
        'uvicorn.protocols',
        'uvicorn.protocols.http',
        'uvicorn.protocols.http.auto',
        'uvicorn.protocols.websockets',
        'uvicorn.protocols.websockets.auto',
        'uvicorn.lifespan',
        'uvicorn.lifespan.on',
        'email.mime.text',
        'email.mime.multipart',
        'extract_msg',
        'pypdf',
        'docx',
        'reportlab',
        'reportlab.pdfgen',
        'reportlab.lib',
        'reportlab.platypus',
        'openpyxl',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='backend_server',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
