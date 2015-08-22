#!/bin/bash
APIKEY="<your API key here>"
SCANTOOL="/path/to/executable/scan-tool"

if [[ ! -x "$SCANTOOL" ]]
then
  echo "The provided scan tool is not an executable file!"
  exit 1
fi

if [[ -z "$APIKEY" ]]
then
  echo "The API key is empty!"
  exit 1
fi

$SCANTOOL --apikey "$APIKEY" --silent /files/to/scan/*.dat
EXITCODE=$?
if [[ $EXITCODE -ne 0 ]]
then
  echo "Something went wrong while executing the scan tool."
  exit 1
fi

exit 0
