# ChangeLog for scan-tool

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