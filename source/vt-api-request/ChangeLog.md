# ChangeLog for vt-api-request

## Version 1.0.3 (2016-03-24)
  - add option to read the API key from a file
    This way the API key will not appear in the process list and/or shell
    history. However, the file name can still be  seen, so proper file
    permissions should be set to avoid that other users can read the API key.

## Version 1.0.2 (2015-12-30)
  - fix spelling + add missing whitespace in text message

## Version 1.0.1 (2015-08-30)
  - minor text fixes

## Version 1.0.0 (2015-08-29)
  - Return code for failed scans/requests is now different from the
    return code for invalid parameter usage to allow a proper distinction
    between those two.

## Version 0.9.1 (2015-08-29)
  - add initial wait parameter (--initial-wait | --wait)

## Version 0.9.0 (2015-08-29)
  - add help text and version information
