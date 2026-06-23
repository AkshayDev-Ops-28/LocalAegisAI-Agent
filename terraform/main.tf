# INTENTIONALLY FLAWED — DO NOT DEPLOY TO REAL AWS
# Missing: encryption, versioning, public access block, logging

resource "aws_s3_bucket" "aegis_data" {
  bucket = "localaegis-data-bucket"
}
