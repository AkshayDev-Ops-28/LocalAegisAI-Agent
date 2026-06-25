resource "aws_s3_bucket" "aegis_data" {
  bucket = "localaegis-data-bucket"
}

resource "aws_s3_bucket_versioning" "aegis_data" {
  bucket = aws_s3_bucket.aegis_data.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "aegis_data" {
  bucket = aws_s3_bucket.aegis_data.id

  block_public_acls   = true
  block_public_policy = true
  ignore_public_acls  = true
  restrict_public_buckets = true
}


    expiration {
      days = 90
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_sns_topic" "aegis_data" {
  name              = "localaegis-data-topic"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_s3_bucket_notification" "aegis_data" {
  bucket = aws_s3_bucket.aegis_data.id
  topic {
    topic_arn = aws_sns_topic.aegis_data.arn
    events    = ["s3:ObjectCreated:*"]
  }
}

resource "aws_s3_bucket" "aegis_logging" {
  bucket = "localaegis-logging-bucket"
}

resource "aws_s3_bucket_versioning" "aegis_logging" {
  bucket = aws_s3_bucket.aegis_logging.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "aegis_logging" {
  bucket = aws_s3_bucket.aegis_logging.id

  block_public_acls   = true
  block_public_policy = true
  ignore_public_acls  = true
  restrict_public_buckets = true
}


    expiration {
      days = 90
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_notification" "aegis_logging" {
  bucket = aws_s3_bucket.aegis_logging.id
  topic {
    topic_arn = aws_sns_topic.aegis_data.arn
    events    = ["s3:ObjectCreated:*"]
  }
}

resource "aws_s3_bucket_logging" "aegis_data" {
  bucket = aws_s3_bucket.aegis_data.id

  target_bucket = aws_s3_bucket.aegis_logging.id
  target_prefix = "/logs/"
}