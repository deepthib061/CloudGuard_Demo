import boto3
import os

# TODO: remove before pushing (developer forgot!)
AWS_ACCESS_KEY_ID =""
aws_secret_access_key =""
STRIPE_API_KEY =""

s3 = boto3.client("s3", aws_access_key_id=AWS_ACCESS_KEY_ID)
