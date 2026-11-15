# ZeroShield CBOM scan node: AMI build kit (@VERSION@)

This kit builds the scan node as an Amazon Machine Image in your own AWS account. Nothing is pulled from a ZeroShield
registry: the build instance loads the scan node image file you downloaded from ZeroShield.


> **Building the AMI needs internet access** ([what it downloads](#needs-internet-access-to-build)). For an
> air-gapped network, use the scan node image file or the Helm chart instead: no build, no internet at install time.

## What you need

* [Packer](https://developer.hashicorp.com/packer) 1.10 or later and AWS credentials that can launch an instance and
  create an AMI in the region you choose (Packer's `amazon` plugin; Canonical's Ubuntu 24.04 LTS AMI, owner
  099720109477).
* From ZeroShield, **CBOM > Sources > Scan nodes > Add scan node**: `scan-node-@VERSION@.tar.gz` and
  `scan-node-@VERSION@.tar.gz.sha256` (**Download scan node image**).

## Needs internet access to build

Building the AMI downloads software, so it cannot run in an air-gapped network:

* **Internet access**, for: Packer's `amazon` plugin (`packer init`, from GitHub), the AWS APIs, Canonical's Ubuntu
  24.04 LTS AMI as the source image, and Ubuntu packages on the build instance (`apt-get update`, `apt-get upgrade`,
  `apt-get install docker.io ...`, from the Ubuntu archive; the build subnet needs a route to it). The kit has no
  setting for an apt mirror.

**No internet where you build?** Run the scan node without a build: the **scan node image file** (`docker load` on
any Linux host with Docker, then the `docker run --pull never` command that **Add scan node** shows), or the **Helm
chart** with the image pushed to your own registry. Neither needs internet access at install time; the node itself
only needs outbound HTTPS to the ZeroShield API.

## Build

Run it as one block: nothing is built if the image file fails its SHA-256 check.

```sh
unzip cbom-scan-node-ami-kit-@VERSION@.zip && cd cbom-scan-node-ami-kit-@VERSION@ && \
cp /path/to/scan-node-@VERSION@.tar.gz /path/to/scan-node-@VERSION@.tar.gz.sha256 . && \
sha256sum -c scan-node-@VERSION@.tar.gz.sha256 && \
packer init ami.pkr.hcl && \
packer build -var region=ap-south-1 ami.pkr.hcl      # your region; -var subnet_id=... for a private subnet
# -> AMI zeroshield-cbom-scan-node-@VERSION@-<timestamp> (encrypted root volume, IMDSv2 only)
```

The build instance loads the image file (`docker load`, as `@IMAGE@`), installs Docker and the node's systemd unit,
then removes its SSH host keys, cloud-init state and machine id, so every instance gets its own.

## Launch

Launch the AMI in the VPC that reaches your targets and paste the cloud-config that **Add scan node > AWS AMI**
shows after you create the node as the instance's user data. cloud-init writes `/etc/zs-node/env` (mode 0600) and
the node starts and registers. It needs outbound HTTPS to the ZeroShield API only.

## Files

| File | What it does |
|---|---|
| `ami.pkr.hcl` | Packer `amazon-ebs` build; `node_image_archive` defaults to `scan-node-@VERSION@.tar.gz` in this directory |
| `scripts/install.sh` | Installs Docker, loads the image file, installs the unit; clears per-instance identity |
| `files/zs-node-run`, `files/zs-scan-node.service` | Runs the node container with the settings in `/etc/zs-node/env` |
