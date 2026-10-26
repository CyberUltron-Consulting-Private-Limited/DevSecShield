resource "aws_db_instance" "plain" {
  storage_encrypted = false
}

resource "aws_s3_bucket" "logs" {
}
