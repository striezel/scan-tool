# ChangeLog for scan-tool

## Version 0.51 (2021-11-18)

The C++ standard used during compilation has been raised from C++14 to C++17.
Most compilers should support that by now.

The minimum required CMake version for compiling the project is raised from 2.8
to 3.8.

JSON parsing is now handled by the simdjson library and not by JsonCpp anymore.

## Version 0.50 (2019-10-06)

The C++ standard used during compilation has been raised from C++11 to C++14.
Most compilers should support that by now.

## Version 0.49 (2017-06-05)
  - add InstallShield Cabinet handler: If told via the commend line
    option --installshield, scan-tool will extract InstallShield Cabinet
    archives and scan each contained file individually before scanning the
    archive itself.

## Version 0.48 (2017-06-04)
  - add Rar handler: If told via the commend line option --rar, scan-tool will
    extract Roschal archives and scan each contained file individually before
    scanning the archive itself. However, due to the proprietary nature of the
    archive format, it is possible that not all files can be extracted from
    the archive.

## Version 0.47 (2017-06-03)
  - add 7-Zip handler: If told via the commend line option --7zip, scan-tool
    will extract 7-Zip archives and scan each contained file individually
    before scanning the archive itself.

## Version 0.46.1 (2017-04-21)
  - add info about strategy "scan and forget" to help message

## Version 0.46 (2017-04-06)
  - add new scan strategy "scan and forget" that submits every file for
    scanning but will never get any scan reports for them

## Version 0.44 (2017-02-28)
  - Do not abort if report could not be retrieved because the file to scan is
    still in scan queue of VirusTotal. Instead, scan-tool will try to get the
    report again at a later time when the reports of all the other queued files
    will be retrieved. This only affects the scan strategies "default" and
    "no-rescan".

## Version 0.42 (2016-08-14)
  - consider number of files in archives for count of total and processed
    files, too

## Version 0.41 (2016-08-11)
  - skip symbolic links in archives

## Version 0.40 (2016-08-07)
  - add an option to ignore errors that might occur during the extraction of
    archive files: --ignore-extraction-errors

## Version 0.39 (2016-07-20)
  - add Cabinet handlers: If told via the command line option --cab, scan-tool
    will extract Microsoft Cabinet archives and scan each contained file
    individually before scanning the file itself.

## Version 0.38 (2016-05-01)
  - add Ar, ISO 9660 and XZ handlers: If told via command line options --ar,
    --iso / --iso9660, --xz scan-tool will extract Ar archives, ISO 9660 disk
    images, XZ compressed streams and scan each contained file individually
    before scanning the file itself.

## Version 0.37 (2016-04-28)
  - add tar and gzip handlers: if told via command line options --tar and/or
    --gzip, scan-tool will extract tar and/or gzipfile  and scan each contained
    file individually before scanning the tar/gz file itself

## Version 0.36b (2016-04-25)
  - refactoring for handlers classes:
    Handlers are now part of the scan strategy class and get invoked by the
    scan strategies directly. This allows us to apply handlers recursively,
    e.g. allows the ZipHandler to scan files in a zip file within a zip file.

## Version 0.36 (2016-04-01)
  - add ZIP handler: if told via command line option --zip, scan-tool will
    extract ZIP archives and scan each file individually before scanning the
    ZIP archive itself

## Version 0.34 (2016-03-29)
  - add scan strategy "no-rescan" which will never perform rescans on files
    that have old/outdated reports (rest works like default strategy)

## Version 0.33 (2016-03-28)
  - add second scan strategy
  - current strategies: "default" (usual scan strategy as before), and
    "direct" (submits/scans file first, regardless of existing reports)

## Version 0.32 (2016-03-24)
  - add option to read the API key from a file
    This way the API key will not appear in the process list and/or shell
    history. However, the file name can still be  seen, so proper file
    permissions should be set to avoid that other users can read the API key.

## Version 0.31 (2016-03-05)
  - add option to set a custom location for cache directory

## Version 0.30 (2016-02-29)
  - minor adjustments under the hood
  - set version to same version as current scan-tool-cache

## Version 0.28 (2016-02-17)
  - Transition and integrity check features from scan-tool 0.27b and earlier
    are moved to scan-tool-cache, because they are cache-related operations.

## Version 0.27b (2016-02-03)
  - improve integrity check (again)

## Version 0.27 (2016-02-02)
  - integrity check will now check SHA256 hash against cache file name

## Version 0.26b (2016-01-09)
  - fix mistake in text message

## Version 0.26 (2016-01-09)
  - change directory structure of request cache (again)
  - add option for automatic transition from older request cache structures
    (both the first from v0.20 till v0.21 and the later structure from v0.22
    till v0.25) to new request cache structure

## Version 0.25 (2016-01-04)
  - improve rescan requests

    Actually use rescan API for rescanning files instead of submitting the
    whole file again. This is faster and saves bandwith.

## Version 0.24 (2015-12-29)
  - (Linux only) show progress when SIGUSR1 or SIGUSR2 is received

## Version 0.23b (2015-12-24)
  - add missing line break to help text

## Version 0.23 (2015-12-20)
  - implement option to check report cache integrity
  - delete a corrupted cache file automatically when the program encounters
    such a file

## Version 0.22 (2015-12-19)
  - change directory structure of request cache

## Version 0.21 (2015-12-15)
  - show number of processed files when program execution is interrupted via
    interrupt (Ctrl+C) or SIGTERM

## Version 0.20 (2015-12-13)
  - implement request cache

## Version 0.19 (2015-12-12)
  - use std::set instead of std::unordered_set for file list

    Enforces a reproducible order on iteration over file list.

## Version 0.18 (2015-12-11)
  - add file size check to re-scan requests

    Avoids errors due to (re-)scan of files that are too large to be scanned
    via the API.

## Version 0.17 (2015-12-06)
  - add signal handlers to show statistics before signal-induced termination

    This way the user can still get a partial(!) summary of the infected files,
    large files, queued files before the program  exits due to the caught
    signal. Only SIGINT and SIGTERM are caught in that way. Other signal are
    unaffected.

## Version 0.16 (2015-12-05)
  - scan-tool: trigger re-scan of a file, if the latest report exeeds a certain
    maximum age. User can specify the maximum age in days via command line.

## Version 0.15 (2015-11-15)
  - Only display size of files that could not be scanned because of their size
    in non-silent mode.
  - These files are now displayed at the end of the program execution (after
    the files that were queued for scan but the scan has not completed yet).

## Version 0.14 (2015-11-01)
  - display size of files that could not be scanned because their file size
    exceeds the allowed size for scans / uploads

## Version 0.13 (2015-08-31)
  - fix missing character in output to stdout

## Version 0.12 (2015-08-30)
  - add option to read the files that shall be scanned from a text file,
    one per line

## Version 0.11 (2015-08-27)
  - list files that could not be scanned in time at the end, because they may
    be potentially unsafe/infected

## Version 0.10 (2015-08-24)
  - show OK message, if no infected files were found

## Version 0.09 (2015-08-24)
  - implement check for maximum file size limit

## Version 0.08 (2015-08-23)
  - show scan date in list of infected files

## Version 0.07 (2015-08-22)
  - make progam even less verbose when run with --silent option

## Version 0.06 (2015-08-22)
  - retrieve reports of files that were queued for scan at the end, before the
    final result listing is shown

## Version 0.05 (2015-08-22)
  - raise default limit for false positives from 2 to 3

## Version 0.04 (2015-08-22)
  - fix listing of infected files to only include the engines that detected a
    threat and not the engines that found nothing

## Version 0.03 (2015-08-22)
  - list possibly infected files (again) after all files are scanned

## Version 0.02 (2015-08-22)
  - fix initialization of scanner

## Version 0.01 (2015-08-22)
  - initial, very simple version
