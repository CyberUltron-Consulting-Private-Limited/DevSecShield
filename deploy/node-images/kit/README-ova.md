# ZeroShield CBOM scan node: OVA build kit (@VERSION@)

This kit builds the scan node as a VMware OVA on your own build machine. Nothing is pulled from a ZeroShield
registry: the build loads the scan node image file you downloaded from ZeroShield.


> **Building the OVA needs internet access** ([what it downloads](#needs-internet-access-to-build)). For an
> air-gapped network, use the scan node image file or the Helm chart instead: no build, no internet at install time.

## What you need

* A Linux build machine with KVM, `qemu-img`, `python3` and [Packer](https://developer.hashicorp.com/packer) 1.10 or
  later. It downloads Ubuntu 24.04 LTS (cloud image, checked against Canonical's `SHA256SUMS`) and Packer's `qemu`
  plugin.
* From ZeroShield, **CBOM > Sources > Scan nodes > Add scan node**: `scan-node-@VERSION@.tar.gz` and
  `scan-node-@VERSION@.tar.gz.sha256` (**Download scan node image**).

## Needs internet access to build

Building the OVA downloads software, so it cannot run in an air-gapped network:

* **Internet access on the build machine**, for: the Ubuntu 24.04 LTS cloud image and its `SHA256SUMS`
  (`cloud-images.ubuntu.com`), Packer's `qemu` plugin (`packer init`, from GitHub), and Ubuntu packages inside the
  build VM (`apt-get update`, `apt-get upgrade`, `apt-get install docker.io ...`, from the Ubuntu archive). The kit has
  no setting for a local base image or an apt mirror.

**No internet where you build?** Run the scan node without a build: the **scan node image file** (`docker load` on
any Linux host with Docker, then the `docker run --pull never` command that **Add scan node** shows), or the **Helm
chart** with the image pushed to your own registry. Neither needs internet access at install time; the node itself
only needs outbound HTTPS to the ZeroShield API.

## Build

Run it as one block: nothing is built if the image file fails its SHA-256 check.

```sh
unzip cbom-scan-node-ova-kit-@VERSION@.zip && cd cbom-scan-node-ova-kit-@VERSION@ && \
cp /path/to/scan-node-@VERSION@.tar.gz /path/to/scan-node-@VERSION@.tar.gz.sha256 . && \
sha256sum -c scan-node-@VERSION@.tar.gz.sha256 && \
packer init ova.pkr.hcl && \
packer build -var build_password="$(openssl rand -hex 16)" ova.pkr.hcl
# -> output-ova/zeroshield-cbom-scan-node-@VERSION@.ova
```

The build VM loads the image file (`docker load`, as `@IMAGE@`), installs Docker, the node's systemd unit and
open-vm-tools, then removes its build password, SSH host keys, cloud-init state and machine id, so every VM deployed
from the OVA gets its own.

## Deploy

Deploy the OVA in vSphere and fill in the vApp properties that **Add scan node > OVA appliance** shows after you
create the node: `zs.api_url`, `zs.registration_token`, and optionally `zs.https_proxy` and `zs.mode` (`agent`).
At first boot they are written to `/etc/zs-node/env` and the node starts and registers. Values with spaces, quotes
or newlines are refused.

Hyper-V does not read OVAs: convert the disk (`qemu-img convert -O vhdx`) and write `/etc/zs-node/env` with
cloud-init (NoCloud) or by hand.

## Files

| File | What it does |
|---|---|
| `ova.pkr.hcl` | Packer `qemu` build; `node_image_archive` defaults to `scan-node-@VERSION@.tar.gz` in this directory |
| `scripts/install.sh` | Installs Docker, loads the image file, installs the unit; clears per-VM identity |
| `scripts/make-ova.sh` | Packages the disk as an OVA (streamOptimized VMDK, OVF with vApp properties, SHA-256 manifest) |
| `files/zs-node-run`, `files/zs-scan-node.service` | Runs the node container with the settings in `/etc/zs-node/env` |
| `files/zs-ovf-env`, `files/zs-ovf-env.service` | Turns the vApp properties into `/etc/zs-node/env` at first boot |
| `ovf/zs-scan-node.ovf.in` | OVF descriptor: 2 vCPU, 2 GB, one disk, VMXNET3, the vApp properties |
