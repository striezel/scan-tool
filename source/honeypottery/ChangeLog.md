# ChangeLog for honeypottery

## Version 0.0.7 (2021-11-18)

The C++ standard used during compilation has been raised from C++14 to C++17.
Most compilers should support that by now.

The minimum required CMake version for compiling the project is raised from 2.8
to 3.8.

JSON parsing is now handled by the simdjson library and not by JsonCpp anymore.

## Version 0.0.6 (2019-10-06)

The C++ standard used during compilation has been raised from C++11 to C++14.
Most compilers should support that by now.

## Version 0.0.5 (2016-03-24)
  - add option to read the API key from a file
    This way the API key will not appear in the process list and/or shell
    history. However, the file name can still be  seen, so proper file
    permissions should be set to avoid that other users can read the API key.

## Version 0.0.4 (2015-12-06)
  - fix typo in error message

## Version 0.0.3 (2015-11-15)
  - fix typos in help text

## Version 0.0.2 (2015-08-30)
  - remove unnecessary output line

## Version 0.0.1 (2015-08-29)
  - initial version
