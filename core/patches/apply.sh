#!/bin/sh
# Backports fixes from newer Xray-core into the vendored v26.2.6 sources.
# Run from core/ after `go mod vendor`.
set -eu
X=vendor/github.com/xtls/xray-core

# XTLS/Xray-core 0ac13bd9 (v26.3.23): drop the bogus "SeqPlacement must be path
# when SessionPlacement is path" check. The transport already supports any
# combination; newer panels generate such configs.
f=$X/infra/conf/transport_internet.go
grep -q 'SeqPlacement must be path when SessionPlacement is path' "$f"
awk '
  /if c.SessionPlacement == "path" \{/ && !done { skip = 3; done = 1 }
  skip > 0 { skip--; next }
  { print }
' "$f" > "$f.tmp" && mv "$f.tmp" "$f"
! grep -q 'SeqPlacement must be path' "$f"
echo "patched: seq/session placement check"

# REALITY clients send their Xray version in the handshake, and servers may
# reject old ones (minClientVer); they then answer like the real site
# ("REALITY: received real certificate"). Report the current release.
f=$X/core/core.go
sed -i.bak -e 's/Version_x byte = 26/Version_x byte = 26/' -e 's/Version_y byte = 2$/Version_y byte = 10/' -e 's/Version_z byte = 6$/Version_z byte = 21/' "$f" && rm -f "$f.bak"
grep -q 'Version_y byte = 10' "$f" && grep -q 'Version_z byte = 21' "$f"
echo "patched: reported version 26.10.21"
