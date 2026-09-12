#!/usr/bin/env bash
set -euo pipefail
# TODO: mkdir -p /etc/systemd/system/svc.service.d by hand before site config.
# The directory is named here and never created, which is exactly the state R4
# exists to report. A bare grep over the file called this conformant.
install -m 0755 bin/svc /usr/local/bin/svc
