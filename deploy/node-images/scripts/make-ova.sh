#!/bin/sh
# Package a qcow2 disk as an OVA for VMware: streamOptimized VMDK + OVF descriptor (vApp properties for the scan
# node's settings, guestinfo transport) + SHA-256 manifest, in the order OVF requires (descriptor first).
#   sh scripts/make-ova.sh <disk.qcow2> <version>
set -eu
QCOW=$1
VERSION=$2
DIR=$(dirname "$QCOW")
NAME=zeroshield-cbom-scan-node-$VERSION
HERE=$(cd "$(dirname "$0")/.." && pwd)
command -v qemu-img >/dev/null || { echo "qemu-img is required" >&2; exit 1; }
qemu-img convert -O vmdk -o subformat=streamOptimized,adapter_type=lsilogic "$QCOW" "$DIR/$NAME-disk1.vmdk"
CAPACITY=$(qemu-img info --output=json "$QCOW" | python3 -c "import json,sys; print(json.load(sys.stdin)['virtual-size'])")
SIZE=$(stat -c %s "$DIR/$NAME-disk1.vmdk")
sed -e "s/@VERSION@/$VERSION/g" -e "s/@DISK@/$NAME-disk1.vmdk/g" -e "s/@SIZE@/$SIZE/g" -e "s/@CAPACITY@/$CAPACITY/g" \
  "$HERE/ovf/zs-scan-node.ovf.in" > "$DIR/$NAME.ovf"
(cd "$DIR" && for f in "$NAME.ovf" "$NAME-disk1.vmdk"; do printf 'SHA256(%s)= %s\n' "$f" "$(sha256sum "$f" | cut -d' ' -f1)"; done > "$NAME.mf")
(cd "$DIR" && tar -cf "$NAME.ova" --format=ustar "$NAME.ovf" "$NAME.mf" "$NAME-disk1.vmdk")
echo "$DIR/$NAME.ova"
