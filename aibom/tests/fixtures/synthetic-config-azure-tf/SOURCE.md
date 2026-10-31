# synthetic-config-azure-tf

Hand-derived 2026-10-27 from `main.tf`, `test_cbom_posture_terraform.py`
(purge protection / web app TLS), and the Azure coverage rows. Values were not
taken from a product scan.

- `azurerm_key_vault.vault` omits `purge_protection_enabled`. The reviewed
  `azure.keyvault.purge_protection` finding_default raises
  `KMS_KEY_DELETION_UNPROTECTED` while the service layer stays UNKNOWN.
- `azurerm_storage_account.logs` has no modeled encryption attribute on the
  block; the service layer is UNKNOWN (`attribute_not_modeled`) with an empty
  finding set.
- `azurerm_linux_web_app.app` sets `https_only = true`, yielding
  `ENCRYPTED_DECLARED` on transport as the encrypted positive control (peer to
  an at-rest enable flag on managed storage).

No secrets are planted in this tree.
