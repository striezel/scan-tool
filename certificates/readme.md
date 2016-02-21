## Certificates for peer verification

This directory contains the certificates for peer verification required by the
Metascan Online subdomain that is used for initiating scans. Unfortunately,
the certificates that were used by libcurl on my Debian-based system could not
verify the identity of the host, so I extracted them from the Iceweasel
certificate store with the help of the db2pem script provided by cURL. See
https://github.com/curl/curl/blob/master/lib/firefox-db2pem.sh for the current
version of that script. (It requires the certutil binary from the package
[libnss3-tools](https://packages.debian.org/libnss3-tools) to run.)

It should be enough to specify the path to metascan.crt when using the
scan-tool-mso utility, e.g.

  ./scan-tool-mso --certfile /path/to/metascan.crt <other arguments here> ...
