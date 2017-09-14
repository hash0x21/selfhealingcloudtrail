# AWS Provider Info
provider "aws" {
  region = "us-east-1"
  shared_credentials_file = "/Users/<username>/.aws/credentials" # <--- PLACE AWS CREDENTIALS FILE
  profile = "lethal_good_admin"
}

# AWS Account Variables 
variable "account_name" { 
  type = "string"
  default = "lethal"
}
variable "account_id" {
  type = "string"
  default = "074726884951"
}
variable "region" {
  type = "string" 
  default = "us-east-1"
}

variable "kms_access_group" {
  type = "list"
  default = [
    "arn:aws:iam::074726884951:root", 
    "arn:aws:iam::074726884951:user/good_admin", 
    "arn:aws:iam::074726884951:user/bad_admin"
  ]
}
variable "kms_admins" {
  type = "list"
  default = [
    "arn:aws:iam::074726884951:root", 
    "arn:aws:iam::074726884951:user/good_admin", 
    "arn:aws:iam::074726884951:user/bad_admin"
  ] 
}

####################################
#### CloudWatch Event Resources #### 
####################################

#### CLOUDWATCH ####
# Create CloudWatch Event Rule
resource "aws_cloudwatch_event_rule" "cloudtrail" {
  name        = "cloudtrail-${var.account_name}-disable"
  description = "When CloudTrail is Deleted, Updated, or Stopped - Notify Admins & Re-Enable Service via Lambda"
  event_pattern = <<PATTERN
{
  "source": [
    "aws.cloudtrail"
  ],
  "detail-type": [
    "AWS API Call via CloudTrail"
  ],
  "detail": {
    "eventSource": [
      "cloudtrail.amazonaws.com"
    ],
    "eventName": [
      "StopLogging",
      "DeleteTrail",
      "UpdateTrail"
    ]
  }
}
PATTERN
}

# Create CloudWatch Event Target - SNS Topic 
resource "aws_cloudwatch_event_target" "sns" {
  rule      = "${aws_cloudwatch_event_rule.cloudtrail.name}"
  target_id = "SendToSNS"
  arn       = "${aws_sns_topic.cloudtrail.arn}"
}

# Create CloudWatch Event Target - Lambda Function 
resource "aws_cloudwatch_event_target" "lambda" {
  rule      = "${aws_cloudwatch_event_rule.cloudtrail.name}"
  target_id = "SendToLambda"
  arn       = "${aws_lambda_function.cloudtrail-lambda.arn}"
}

#### SNS ####
# Create SNS Topic for CloudWatch Event to Publish To 
resource "aws_sns_topic" "cloudtrail" {
  name = "cloudtrail-${var.account_name}-disable-sns"
  display_name = "CTDisabled"
}
 
# Create SNS Topic Policy 
resource "aws_sns_topic_policy" "cloudtrail" {
  arn = "${aws_sns_topic.cloudtrail.arn}"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Id": "__default_policy_ID",
  "Statement": [
    {
      "Sid": "__default_statement_ID",
      "Effect": "Allow",
      "Principal": {
        "AWS": "*"
      },
      "Action": [
        "SNS:GetTopicAttributes",
        "SNS:SetTopicAttributes",
        "SNS:AddPermission",
        "SNS:RemovePermission",
        "SNS:DeleteTopic",
        "SNS:Subscribe",
        "SNS:ListSubscriptionsByTopic",
        "SNS:Publish",
        "SNS:Receive"
      ],
      "Resource": "${aws_sns_topic.cloudtrail.arn}",
      "Condition": {
        "StringEquals": {
          "AWS:SourceOwner": "${var.account_name}"
        }
      }
    },
    {
      "Sid": "AWSEvents_CloudTrailDisable_Id503607013484",
      "Effect": "Allow",
      "Principal": {
        "Service": "events.amazonaws.com"
      },
      "Action": "sns:Publish",
      "Resource": "${aws_sns_topic.cloudtrail.arn}"
    }
  ]
}
POLICY
}  

/*
# Create Subscription to SNS Topic 
# EMAIL NOT SUPPORTED SO IGNORING... 
resource "aws_sns_topic_subscription" "cloudwatch" {
  topic_arn = "${aws_sns_topic.cloudwatch.arn}"
  protocol  = "email"

} */

#### LAMBDA FUNCTION #### 
# Create Lambda Function Which Re-Enables CloudTrail on Delete/Update/Stop Calls 
data "archive_file" "cloudtrail-lambda-zip" {
  type        = "zip"
  source_file  = "${path.module}/cloudtrail_lambda.py"
  output_path = ".terraform/cloudtrail_mod/cloudtrail_lambda.zip"
}


resource "aws_lambda_function" "cloudtrail-lambda" {
  filename         = "${data.archive_file.cloudtrail-lambda-zip.output_path}"
  function_name    = "cloudtrail-${var.account_name}-enable"
  role             = "${aws_iam_role.cloudtrail-lambda-role.arn}"
  handler          = "cloudtrail_lambda.lambda_handler"
  runtime          = "python2.7"
  description      = "Lambda Function to ReEnable CloudTrail"
  source_code_hash = "${data.archive_file.cloudtrail-lambda-zip.output_base64sha256}"
}

# Create Lambda Function Permissions To Allow CloudWatch To Execute Function 
resource "aws_lambda_permission" "cloudtrail-lambda" {
  statement_id   = "AllowExecutionFromCloudWatch"
  action         = "lambda:InvokeFunction"
  function_name  = "${aws_lambda_function.cloudtrail-lambda.function_name}"
  principal      = "events.amazonaws.com"
  source_arn     = "${aws_cloudwatch_event_rule.cloudtrail.arn}"
}

# Create Lambda Role 
resource "aws_iam_role" "cloudtrail-lambda-role" {
  name = "cloudtrail-${var.account_name}-lambda-role"

  assume_role_policy = <<EOF
{  
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

/* 
Create Lambda Role Policy 
Policy allows Lambda Function to create CloudWatch Logs 
And also allows full access to CloudTrail to be able to make changes to CloudTrail 
*/ 
resource "aws_iam_role_policy" "cloudtrail-lambda-role" {
   name = "cloudtrail-${var.account_name}-lambda-role"
   role = "${aws_iam_role.cloudtrail-lambda-role.id}"
   policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogStreams"
      ],
      "Resource": "arn:aws:logs:*:*:*" 
    },
    {
      "Effect": "Allow",
      "Action": [
        "sns:AddPermission",
        "sns:CreateTopic",
        "sns:DeleteTopic",
        "sns:ListTopics",
        "sns:SetTopicAttributes",
        "sns:GetTopicAttributes"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:CreateBucket",
        "s3:DeleteBucket",
        "s3:ListAllMyBuckets",
        "s3:PutBucketPolicy",
        "s3:ListBucket",
        "s3:GetObject",
        "s3:GetBucketLocation",
        "s3:GetBucketPolicy"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": "cloudtrail:*",
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "iam:*"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "kms:ListKeys",
        "kms:ListAliases"
      ],
      "Resource": "*"
    }
  ]
}
EOF
}


##############################
#### CloudTrail Resources #### 
##############################

# Create Cloudtrail 
resource "aws_cloudtrail" "cloudtrail" {
    name = "${var.account_name}-cloudtrail"
    s3_bucket_name = "lethal-cloudtrail-logs"
    s3_key_prefix = "${var.account_name}"
    enable_logging = true
    include_global_service_events = true
    is_multi_region_trail = true
    enable_log_file_validation = true
    kms_key_id = "" # <--- PLACE KMS ARN HERE
    cloud_watch_logs_role_arn = "${aws_iam_role.cloudtrail_logs.arn}"
    cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}"
    depends_on = ["aws_cloudwatch_log_group.cloudtrail", "aws_iam_role.cloudtrail_logs", "null_resource.sleep"]
}

# Create CloudTrail Role 
resource "aws_iam_role" "cloudtrail_logs" {
    name = "cloudtrail-${var.account_name}-log-role"
    assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

# Create CloudTrail Role Policy to Allow Logs to CloudWatch 
resource "aws_iam_role_policy" "cloudtrail_logs" {
   name = "cloudtrail-${var.account_name}-log-role"
   role = "${aws_iam_role.cloudtrail_logs.id}"
   policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSCloudTrailCreateLogStream",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogStream",
        "logs:PutLogEvents" 
      ],
      "Resource": [
        "${aws_cloudwatch_log_group.cloudtrail.arn}" 
      ]
    }
  ]
}
EOF
}

# Create Cloudwatch Log Group For CloudTrail Logs  
resource "aws_cloudwatch_log_group" "cloudtrail" {
  name = "/cloudtrail/${var.account_name}/${var.account_id}" 
}

# Create Null Resource Which Delays Creation of CloudTrail so CloudWatchLogGroup Is Valid
resource "null_resource" "sleep" {
  provisioner "local-exec" {
    command = "/bin/sleep 15"
  }
}  

##################################
#### S3 Bucket for CloudTrail #### 
##################################

# Create S3 bucket 
resource "aws_s3_bucket" "cloudtrail" {
  bucket = "lethal-cloudtrail-logs"
  acl  = "private" 
  force_destroy = true
  versioning {
    enabled = false
    #mfa_delete = true 
  }
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSCloudTrailAclCheck",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::lethal-cloudtrail-logs"
    },
    {
      "Sid": "AWSCloudTrailWrite",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::lethal-cloudtrail-logs/*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": "bucket-owner-full-control"
        }
      }
    },
    {
      "Sid": "AWSAthenaFullAccess",
      "Effect": "Allow",
      "Principal": {
        "Service": "athena.amazonaws.com"
      },
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::lethal-cloudtrail-logs/*"
    },
    {
      "Sid": "Allow Access to Admins Only", 
      "Effect": "Allow",
      "Principal": {
        "Service" : "cloudtrail.amazonaws.com", 
        "AWS": ["arn:aws:iam::074726884951:root", "arn:aws:iam::074726884951:user/good_admin", "arn:aws:iam::074726884951:user/bad_admin"] 
      },
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::lethal-cloudtrail-logs"
    }
  ]
}
POLICY
}


