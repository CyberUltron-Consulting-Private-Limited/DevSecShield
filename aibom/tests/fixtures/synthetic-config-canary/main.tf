resource "aws_db_instance" "canary" {
  storage_encrypted = false
  password          = "CANARY_POSTURE_SECRET_9f3a"
}
