output "ec2_instance_connect_command" {
  value = "aws ec2-instance-connect ssh --instance-id ${aws_instance.main.id} --connection-type eice"
}