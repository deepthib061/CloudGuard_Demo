import boto3

# TODO: remove before pushing (developer forgot!)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
STRIPE_API_KEY=""

s3 = boto3.client("s3", aws_access_key_id=AWS_ACCESS_KEY_ID)
