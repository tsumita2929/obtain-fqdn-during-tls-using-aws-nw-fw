##################################################################
# VPC, IGW, EIP, NAT GW
###################################################################

#trivy:ignore:AVD-AWS-0178 VPC Flow Logs is not enabled for VPC.
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
}
resource "aws_eip" "nat_eip_1a" {
  domain = "vpc"
}

resource "aws_eip" "nat_eip_1c" {
  domain = "vpc"
}

resource "aws_nat_gateway" "main_nat_gw_1a" {
  allocation_id = aws_eip.nat_eip_1a.id
  subnet_id     = aws_subnet.main_public_subnet_1a.id
  depends_on    = [aws_internet_gateway.main]
}

resource "aws_nat_gateway" "main_nat_gw_1c" {
  allocation_id = aws_eip.nat_eip_1c.id
  subnet_id     = aws_subnet.main_public_subnet_1c.id
  depends_on    = [aws_internet_gateway.main]
}

##################################################################
# Subnet, Route Table (Public 1a)
###################################################################
resource "aws_subnet" "main_public_subnet_1a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "ap-northeast-1a"
  tags = {
    Name = "public_subnet-1a"
  }
}

resource "aws_route_table" "main_public_subnet_1a" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
  route {
    cidr_block = aws_subnet.main_private_subnet_1a.cidr_block
    vpc_endpoint_id = [
      for ss in tolist(aws_networkfirewall_firewall.main.firewall_status[0].sync_states) :
      ss.attachment[0].endpoint_id if ss.availability_zone == "ap-northeast-1a"
    ][0]
  }
  tags = {
    Name = "public-1a"
  }
}

resource "aws_route_table_association" "main_public_subnet_1a" {
  subnet_id      = aws_subnet.main_public_subnet_1a.id
  route_table_id = aws_route_table.main_public_subnet_1a.id
}

##################################################################
# Subnet, Route Table (Public 1c)
###################################################################
resource "aws_subnet" "main_public_subnet_1c" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "ap-northeast-1c"
  tags = {
    Name = "public_subnet-1c"

  }
}

resource "aws_route_table" "main_public_subnet_1c" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
  route {
    cidr_block = aws_subnet.main_private_subnet_1c.cidr_block
    vpc_endpoint_id = [
      for ss in tolist(aws_networkfirewall_firewall.main.firewall_status[0].sync_states) :
      ss.attachment[0].endpoint_id if ss.availability_zone == "ap-northeast-1c"
    ][0]
  }
  tags = {
    Name = "public-1c"
  }
}

resource "aws_route_table_association" "main_public_subnet_1c" {
  subnet_id      = aws_subnet.main_public_subnet_1c.id
  route_table_id = aws_route_table.main_public_subnet_1c.id
}

##################################################################
# Subnet, Route Table (FW Subnet 1a)
###################################################################
resource "aws_subnet" "main_fw_subnet_1a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.100.0/24"
  availability_zone = "ap-northeast-1a"
  tags = {
    Name = "fw_subnet-1a"
  }
}

resource "aws_route_table" "main_fw_subnet_1a" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_nat_gateway.main_nat_gw_1a.id
  }
  tags = {
    Name = "fw-1a"
  }

  lifecycle {
    ignore_changes = [route]
  }
}

resource "aws_route_table_association" "main_fw_subnet_1a" {
  subnet_id      = aws_subnet.main_fw_subnet_1a.id
  route_table_id = aws_route_table.main_fw_subnet_1a.id
}

##################################################################
# Subnet, Route Table (FW Subnet 1c)
###################################################################
resource "aws_subnet" "main_fw_subnet_1c" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.101.0/24"
  availability_zone = "ap-northeast-1c"
  tags = {
    Name = "fw_subnet-1c"
  }
}

resource "aws_route_table" "main_fw_subnet_1c" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_nat_gateway.main_nat_gw_1c.id
  }
  tags = {
    Name = "fw-1c"
  }

  lifecycle {
    ignore_changes = [route]
  }
}

resource "aws_route_table_association" "main_fw_subnet_1c" {
  subnet_id      = aws_subnet.main_fw_subnet_1c.id
  route_table_id = aws_route_table.main_fw_subnet_1c.id
}


##################################################################
# Subnet, Route Table (Private 1a)
###################################################################
resource "aws_subnet" "main_private_subnet_1a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.200.0/24"
  availability_zone = "ap-northeast-1a"
  tags = {
    Name = "private_subnet-1a"
  }
}

resource "aws_route_table" "main_private_subnet_1a" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    vpc_endpoint_id = [
      for ss in tolist(aws_networkfirewall_firewall.main.firewall_status[0].sync_states) :
      ss.attachment[0].endpoint_id if ss.availability_zone == "ap-northeast-1a"
    ][0]
  }
  tags = {
    Name = "private-1a"
  }
}

resource "aws_route_table_association" "main_private_subnet_1a" {
  subnet_id      = aws_subnet.main_private_subnet_1a.id
  route_table_id = aws_route_table.main_private_subnet_1a.id
}

##################################################################
# Subnet, Route Table (Private 1c)
###################################################################
resource "aws_subnet" "main_private_subnet_1c" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.201.0/24"
  availability_zone = "ap-northeast-1a"
  tags = {
    Name = "private_subnet-1c"
  }
}

resource "aws_route_table" "main_private_subnet_1c" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    vpc_endpoint_id = [
      for ss in tolist(aws_networkfirewall_firewall.main.firewall_status[0].sync_states) :
      ss.attachment[0].endpoint_id if ss.availability_zone == "ap-northeast-1c"
    ][0]
  }
  tags = {
    Name = "private-1c"
  }
}

resource "aws_route_table_association" "main_private_subnet_1c" {
  subnet_id      = aws_subnet.main_private_subnet_1c.id
  route_table_id = aws_route_table.main_private_subnet_1c.id
}

##################################################################
# NWFW
###################################################################
resource "aws_networkfirewall_firewall" "main" {
  name                = "nw-fw-test"
  firewall_policy_arn = aws_networkfirewall_firewall_policy.main.arn
  vpc_id              = aws_vpc.main.id
  subnet_mapping {
    subnet_id = aws_subnet.main_fw_subnet_1a.id
  }
  subnet_mapping {
    subnet_id = aws_subnet.main_fw_subnet_1c.id
  }
}

resource "aws_networkfirewall_firewall_policy" "main" {
  name = "net-fw-test-policy"

  firewall_policy {
    stateless_default_actions          = ["aws:forward_to_sfe"]
    stateless_fragment_default_actions = ["aws:forward_to_sfe"]
    stateful_default_actions           = ["aws:drop_established"]

    stateful_engine_options {
      rule_order = "STRICT_ORDER"
    }

    stateful_rule_group_reference {
      priority     = 1
      resource_arn = aws_networkfirewall_rule_group.main.arn
    }

  }
  depends_on = [
    aws_subnet.main_fw_subnet_1a,
    aws_subnet.main_fw_subnet_1c,
    aws_subnet.main_private_subnet_1a,
    aws_subnet.main_private_subnet_1c,
    aws_subnet.main_public_subnet_1a,
    aws_subnet.main_public_subnet_1c
  ]
}

resource "aws_networkfirewall_rule_group" "main" {
  capacity    = 50
  description = "Permits TLS traffic from HOME_NET"
  name        = "tls-test"
  type        = "STATEFUL"
  rule_group {

    stateful_rule_options {
      rule_order = "STRICT_ORDER"
    }

    rules_source {
      stateful_rule {
        action = "ALERT"
        header {
          destination      = "ANY"
          destination_port = "ANY"
          protocol         = "TLS"
          direction        = "ANY"
          source_port      = "ANY"
          source           = "$HOME_NET"
        }
        rule_option {
          keyword  = "sid"
          settings = ["1"]
        }
      }

      stateful_rule {
        action = "PASS"
        header {
          destination      = "ANY"
          destination_port = "ANY"
          protocol         = "TLS"
          direction        = "ANY"
          source_port      = "ANY"
          source           = "$HOME_NET"
        }
        rule_option {
          keyword  = "sid"
          settings = ["2"]
        }
      }
    }
  }
}

resource "aws_networkfirewall_logging_configuration" "main" {
  firewall_arn = aws_networkfirewall_firewall.main.arn
  logging_configuration {
    log_destination_config {
      log_destination = {
        logGroup = aws_cloudwatch_log_group.netfw_log.name
      }
      log_destination_type = "CloudWatchLogs"
      log_type             = "FLOW"
      # log_destination = {
      #   bucketName = aws_s3_bucket.netfw_log.bucket
      #   prefix     = "netfw"
      # }
      # log_destination_type = "S3"
      # log_type             = "FLOW"
    }

    log_destination_config {
      #   log_destination = {
      #     logGroup = aws_cloudwatch_log_group.netfw_log.name
      #   }
      #   log_destination_type = "CloudWatchLogs"
      #   log_type             = "ALERT"
      # }
      log_destination = {
        bucketName = aws_s3_bucket.netfw_log.bucket
        prefix     = "network-firewall"
      }
      log_destination_type = "S3"
      log_type             = "ALERT"
    }
  }
}

#trivy:ignore:AVD-AWS-0017 Log group is not encrypted.
resource "aws_cloudwatch_log_group" "netfw_log" {
  name              = "/aws/network-firewall/tls-test"
  retention_in_days = 30
}

# Access Log Bucket
#trivy:ignore:AVD-AWS-0089 S3 Bucket does not have logging enabled.
#trivy:ignore:AVD-AWS-0090 Bucket does not have versioning enabled.
resource "aws_s3_bucket" "netfw_log" {
  bucket = "aws-netfw-logs-poc-tmt"

  tags = {
    Name = "aws-netfw-logs-poc-tmt"
  }
}

#trivy:ignore:AVD-AWS-0132 Bucket does not encrypt data with a customer managed key.
resource "aws_s3_bucket_server_side_encryption_configuration" "netfw_log" {
  bucket = aws_s3_bucket.netfw_log.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "netfw_log" {
  bucket                  = aws_s3_bucket.netfw_log.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_caller_identity" "current" {}
resource "aws_s3_bucket_policy" "netfw_log" {
  bucket = aws_s3_bucket.netfw_log.id
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Id" : "AWSLogDeliveryWrite20150319",
    "Statement" : [
      {
        "Sid" : "AWSLogDeliveryWrite",
        "Effect" : "Allow",
        "Principal" : {
          "Service" : "delivery.logs.amazonaws.com"
        },
        "Action" : "s3:PutObject",
        "Resource" : "arn:aws:s3:::${aws_s3_bucket.netfw_log.id}/*/AWSLogs/${data.aws_caller_identity.current.account_id}/*",
        "Condition" : {
          "StringEquals" : {
            "s3:x-amz-acl" : "bucket-owner-full-control",
            "aws:SourceAccount" : data.aws_caller_identity.current.account_id
          },
          "ArnLike" : {
            "aws:SourceArn" : "arn:aws:logs:ap-northeast-1:${data.aws_caller_identity.current.account_id}:*"
          }
        }
      },
      {
        "Sid" : "AWSLogDeliveryAclCheck",
        "Effect" : "Allow",
        "Principal" : {
          "Service" : "delivery.logs.amazonaws.com"
        },
        "Action" : "s3:GetBucketAcl",
        "Resource" : "arn:aws:s3:::aws-netfw-logs-poc-tmt",
        "Condition" : {
          "StringEquals" : {
            "aws:SourceAccount" : data.aws_caller_identity.current.account_id
          },
          "ArnLike" : {
            "aws:SourceArn" : "arn:aws:logs:ap-northeast-1:${data.aws_caller_identity.current.account_id}:*"
          }
        }
      }
    ]
  })
}

resource "null_resource" "netfw_log" {
  triggers = {
    bucket = aws_s3_bucket.netfw_log.bucket
  }
  depends_on = [
    aws_s3_bucket.netfw_log
  ]
  provisioner "local-exec" {
    when    = destroy
    command = "aws s3 rm s3://${self.triggers.bucket} --recursive"
  }
}

###################################################################
# EC2 Instant Connect Endpoint
###################################################################
resource "aws_ec2_instance_connect_endpoint" "main_eic" {
  subnet_id          = aws_subnet.main_private_subnet_1a.id
  security_group_ids = [aws_security_group.ssh_eic.id]
  preserve_client_ip = true

  tags = {
    Name = "eic-test"
  }
}

resource "aws_security_group" "ssh_eic" {
  name        = "eic-test-sg"
  description = "EIC Security Group For Test"
  vpc_id      = aws_vpc.main.id

  egress {
    description = "SSH for EC2."
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }
}

###################################################################
# EC2 Instance
###################################################################
data "aws_ssm_parameter" "amazonlinux_2" {
  name = "/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-arm64-gp2"
}

resource "aws_instance" "main" {
  ami             = data.aws_ssm_parameter.amazonlinux_2.value
  instance_type   = "t4g.micro"
  subnet_id       = aws_subnet.main_private_subnet_1a.id
  security_groups = [aws_security_group.ssh_ec2.id]

  root_block_device {
    encrypted = true
  }

  ebs_block_device {
    device_name           = "/dev/sdg"
    volume_size           = 10
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true
  }

  metadata_options {
    http_tokens = "required"
  }

  lifecycle {
    ignore_changes = all
  }
}

resource "aws_security_group" "ssh_ec2" {
  name        = "test-ec2-sg"
  description = "EC2 Instance Security Group For Test"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "SSH From Instant connetct endpoint."
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.ssh_eic.id]
  }

  #trivy:ignore:AVD-AWS-0104 Security group rule allows egress to multiple public internet addresses.
  egress {
    description = "HTTPS."
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
