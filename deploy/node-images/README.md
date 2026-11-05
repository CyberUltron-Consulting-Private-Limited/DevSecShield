# Scan node VM images (AMI, OVA): build it yourself

ZeroShield does not publish these images yet. The CBOM Sources wizard marks them **"Build it yourself (template
provided)"**; Docker and the Helm chart (`deploy/helm/cbom-scan-node`) are the ways that were run end to end.

Both images are Ubuntu 24.04 LTS + Docker + the scan-node container image + a systemd unit. Nothing in them is
specific to one customer: the settings arrive at first boot in `/etc/zs-node/env`, and `zs-scan-node.service`
starts only once that file exists.

| File | What it does |
|---|---|
| `ami.pkr.hcl` | Packer `amazon-ebs` build from Canonical's Ubuntu 24.04 AMI (owner 099720109477), IMDSv2 only, encrypted root volume |
| `ova.pkr.hcl` | Packer `qemu` build from the Ubuntu 24.04 cloud image (checked against Canonical's `SHA256SUMS`), packaged as an OVA by `scripts/make-ova.sh` |
| `scripts/install.sh` | Installs `docker.io`, pulls the node image, installs the unit and run script, clears cloud-init state, SSH host keys and the machine id so every VM gets its own |
| `files/zs-node-run` | `docker run --env-file /etc/zs-node/env -v zs-node:/var/lib/zs-node <image>`; with `ZS_MODE=agent` it also mounts `/` read-only at `/host` (the node then reads only this VM and never gets a credential) |
| `files/zs-scan-node.service` | Starts `zs-node-run` after Docker and first boot; `ConditionPathExists=/etc/zs-node/env` |
| `files/zs-ovf-env`, `files/zs-ovf-env.service` | OVA only: turns the vApp properties into `/etc/zs-node/env` at first boot (open-vm-tools, guestinfo transport) |
| `ovf/zs-scan-node.ovf.in` | OVF 1.0 descriptor: 2 vCPU, 2 GB, one disk, VMXNET3, and the vApp properties below |

## AMI

```sh
cd deploy/node-images
packer init ami.pkr.hcl
packer build -var region=ap-south-1 -var node_image=registry.zeroshield.ai/cbom/scan-node:1.0 ami.pkr.hcl
```

Launch it in the VPC that reaches your targets and paste the cloud-config from **Add scan node > AWS AMI** as user
data. cloud-init writes `/etc/zs-node/env` (mode 0600):

```
ZS_API_URL=https://api.zeroshield.ai
ZS_REGISTRATION_TOKEN=zsr_...
HTTPS_PROXY=http://proxy.example.local:8080     (optional)
ZS_MODE=agent                                   (optional: collect only this instance)
```

The values are written without quotes (Docker's `--env-file` reads them literally).

## OVA (VMware)

```sh
cd deploy/node-images
packer init ova.pkr.hcl
packer build -var node_image=registry.zeroshield.ai/cbom/scan-node:1.0 -var build_password="$(openssl rand -hex 16)" ova.pkr.hcl
# -> output-ova/zeroshield-cbom-scan-node-1.0.ova   (needs KVM, qemu-img and python3 on the build machine)
```

Deploy the OVA and fill in the vApp properties the wizard shows: `zs.api_url`, `zs.registration_token`,
optionally `zs.https_proxy` and `zs.mode` (`agent`). `zs-ovf-env` writes them to `/etc/zs-node/env` once, at
first boot; values with spaces, quotes or newlines are refused. The build user's password is removed before the
image is sealed. Hyper-V does not read OVAs: convert the disk (`qemu-img convert -O vhdx`) and write
`/etc/zs-node/env` with cloud-init (NoCloud) or by hand.

## What was tested

`scan_node/tests/test_wp8b_node_images.py` runs `zs-ovf-env` against a recorded OVF environment and `zs-node-run`
against a stub `docker`, and checks that the templates, the OVF properties, the reader and the wizard's install
text agree. The Packer builds themselves were not run (no AWS account or KVM in the build environment), and
`packer validate` was not run either.
