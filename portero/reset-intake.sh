#!/usr/bin/env bash
set -euo pipefail

: "${PORTERO_SPOOL:?}" "${PORTERO_OFFSET:?}"
SYSTEMCTL=${SYSTEMCTL:-systemctl}

restart() {
  "$SYSTEMCTL" start gluck-portero-mint.service gluck-portero-intake.service
}
trap restart EXIT

"$SYSTEMCTL" stop gluck-portero-intake.service
"$SYSTEMCTL" stop gluck-portero-mint.service

truncate -s 0 -- "$PORTERO_SPOOL"
rm -f -- "$PORTERO_OFFSET"

size=$(stat -c %s -- "$PORTERO_SPOOL")
if [ "$size" != 0 ]; then
  echo "intake spool is $size bytes after truncate" >&2
  exit 1
fi
if [ -e "$PORTERO_OFFSET" ]; then
  echo "mint's spool offset survived removal" >&2
  exit 1
fi
echo "<6>INFO intake spool reset spool_bytes=$size"
