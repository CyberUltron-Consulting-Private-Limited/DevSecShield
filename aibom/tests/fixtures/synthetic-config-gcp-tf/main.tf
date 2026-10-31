resource "google_kms_crypto_key" "app" {
  name = "app-key"
}

resource "google_storage_bucket" "data" {
  name = "my-project-data"
}

resource "google_kms_crypto_key_iam_binding" "open" {
  role    = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  members = ["allUsers"]
}
