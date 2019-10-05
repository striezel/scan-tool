# ChangeLog for scan-tool-mso

## Version 0.07 (2019-10-06)

The C++ standard used during compilation has been raised from C++11 to C++14.
Most compilers should support that by now.

## Version 0.06 (2016-05-15)
  - adjust scan limits for Metadefender public API according to
    https://www.opswat.com/blog/preventing-illegitimate-use-of-metadefender
  - This might be the last update of scan-tool-mso.
    If someone finds a severe bug in scan-tool-mso in the future, then this
    will still get fixed, but do not expect any new features.
    The "original" [scan-tool](../scan-tool/) is a program with similar
    features, but it uses the VirusTotal public API instead of Metadefender.
    Take a look at this program, if you need a tool that still gets updates
    once in a while.

## Version 0.05 (2016-03-31)
  - fix Report::successfulRetrieval() and Report::notFound() so that report
    status is now correct in some rarer cases

## Version 0.04 (2016-03-22)
  - raise file size limit for scans to 140 MB
  - use new *.metadefender.com URLs instead of old *.metascan-online.com URLs
    for scanner requests

## Version 0.03 (2016-02-24)
  - add "burst mode" which does not honour time limits / rate limits

## Version 0.02 (2016-02-20)
  - add option to set custom certificate file for peer verification, similar
    to curl's --cacert option

## Version 0.01 (2016-02-02)
  - initial version (reduced and adjusted copy of scan-tool for VirusTotal)
