# ChangeLog for scan-tool-cache

## Next Version (2025-??-??)

The simdjson libary has been updated from version 1.0.2 to version 3.13.0.

## Version 0.51 (2021-11-18)

The C++ standard used during compilation has been raised from C++14 to C++17.
Most compilers should support that by now.

The minimum required CMake version for compiling the project is raised from 2.8
to 3.8.

JSON parsing is now handled by the simdjson library and not by JsonCpp anymore.

## Version 0.50 (2019-10-06)

The C++ standard used during compilation has been raised from C++11 to C++14.
Most compilers should support that by now.

## Version 0.45 (2017-03-01)
  - minor text fix in cache integrity check

## Version 0.43 (2016-08-27)
  - Bugfix: Cache update operation was not working as expected when a
    cache directory other than the default ~/.scan-tool/vt-cache was used.

## Version 0.35b (2016-03-31)
  - show more output for pending rescans during cache update operation
    (but only in non-silent mode)

## Version 0.35 (2016-03-31)
  - show number of old reports in statistics, too

## Version 0.32 (2016-03-24)
  - add option to read the API key from a file
    This way the API key will not appear in the process list and/or shell
    history. However, the file name can still be  seen, so proper file
    permissions should be set to avoid that other users can read the API key.

## Version 0.31 (2016-03-05)
  - add option to set a custom location for cache directory

## Version 0.30 (2016-02-29)
  - add option to update old files in the request cache

## Version 0.29 (2016-02-27)
  - add option to show some statistics about cache

## Version 0.28 (2016-02-17)
  - initial version with basic features
  - Transition and integrity check features from scan-tool 0.27b and earlier
    are moved to scan-tool-cache, because they are cache-related operations.
