# ChangeLog for scan-tool

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
