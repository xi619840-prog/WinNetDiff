# Third-party runtime and build notices

WinNetDiff application source is MIT licensed, Copyright (c) 2026 Alden. Its Python source uses the standard library. Source execution calls the user's installed Windows APIs and utilities; vendor drivers and cleanup utilities are not redistributed.

An EXE produced by the build script contains Python interpreter/runtime files and Tcl/Tk for the GUI. Their licenses are separate from the application's MIT license. The build script copies the interpreter's available license notice into `PYTHON_LICENSE.txt` and the Tcl/Tk notices into `TCL_LICENSE.txt` and `TK_LICENSE.txt`. See the [Python license](https://docs.python.org/3/license.html). The Tcl/Tk notice copies in `third_party/` were retrieved from the official Tcl/Tk 8.6 source branches on 2026-10-24; preserve their actual copyright holders. Review the final bundle's runtime versions and notices before public distribution.

The build uses PyInstaller 6.22.3 and its hooks, with other dependencies pinned in `requirements-build.txt`. PyInstaller's GPL bootloader exception permits application bundles to follow the application/dependency licenses; see the [official license description](https://pyinstaller.org/en/stable/license.html). PyInstaller source is not modified by this project. Build packages are not added to source-mode runtime requirements.

Public release provenance and SHA-256 checksums describe the artifact origin and bytes. They are not a code-signing certificate or a claim of universal software safety.
