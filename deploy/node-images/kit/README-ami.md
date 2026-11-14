# ZeroShield CBOM scan node: AMI build kit (@VERSION@)

This kit builds the scan node as an Amazon Machine Image in your own AWS account. Nothing is pulled from a ZeroShield
registry: the build instance loads the scan node image file you downloaded from ZeroShield.

## What you need

* [Packer](https://developer.hashicorp.com/packer) 1.10 or later and AWS credentials that can launch an instance and
  create an AMI in the region you choose (Packer's `amazon` plugin; Canonical's Ubuntu 24.04 LTS AMI, owner
  099720109477).
* From ZeroShield, **CBOM > Sources > Scan nodes > Add scan node**: `scan-node-@VERSION@.tar.gz` and
  `scan-node-@VERSION@.tar.gz.sha256` (**Download scan node image**).

## Build

```sh
unzip cbom-scan-node-ami-kit-@VERSION@.zip && cd cbom-scan-node-ami-kit-@VERSION@
cp /path/to/scan-node-@VERSION@.tar.gz /path/to/scan-node-@VERSION@.tar.gz.sha256 .
sha256sum -c scan-node-@VERSION@.tar.gz.sha256
packer init ami.pkr.hcl
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
