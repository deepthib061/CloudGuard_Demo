resource "aws_security_group_rule" "ssh" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_s3_bucket" "data" {
  bucket = "my-company-data"
  acl    = "public-read"
}
