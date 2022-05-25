############################################################
# Provider And Resource Group Definition
############################################################

# AWS Provider source and version being used
terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/aws"
      version = "~> 4.15"
    }
  }
}

# Configure AWS Provider
provider "aws" {
  region = "${var.region}"
}


############################################################
# Public IP (we use this to configure firewall)
############################################################

# Get Public IP of my current system
data "http" "public_IP" {
  url = "https://ipinfo.io/json"
  request_headers = {
    Accept = "application/json"
  }
}

############################################################
# Local variables used in this template
############################################################
# Define local variables which we will use across number of systems
# Reference variables from main variables.tf file
# If you prefer to add different IP as source, change 'public_ip' variable to match
locals {
  public_ip = jsondecode(data.http.public_IP.body).ip
  config_file = yamldecode(file(var.system_config_file))
}


############################################################
# Networking Setup
############################################################

# Define primary network range (10.0.0.0/16)
resource "aws_vpc" "main" {
  cidr_block       = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  tags = {
   Name = "${var.prefix}-network"
  }
}

# Internet Gateway for Public Subnet
resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.main.id

  tags = {
   Name = "${var.prefix}-gateway"
  }
}

# Define Route Table (access everywhere)
resource "aws_route_table" "main" {
    vpc_id = "${aws_vpc.main.id}"
    route {
        cidr_block = "0.0.0.0/0" 
        gateway_id = "${aws_internet_gateway.gw.id}" 
    }

  tags = {
   Name = "${var.prefix}-route-table"
  }
}

# Define LAN for Windows Servers
resource "aws_subnet" "windows-servers" {
  depends_on = [aws_internet_gateway.gw]
  vpc_id     = aws_vpc.main.id
  cidr_block = var.windows_server_subnet_cidr
  map_public_ip_on_launch = true
  
  availability_zone = var.region
  tags = {
   Name = "${var.prefix}-windows-server-lan"
  }
}

# Define LAN for Linux Servers
resource "aws_subnet" "linux-servers" {
  depends_on = [aws_internet_gateway.gw]
  vpc_id     = aws_vpc.main.id
  cidr_block = var.linux_server_subnet_cidr
  map_public_ip_on_launch = true
  availability_zone = var.region
  tags = {
   Name = "${var.prefix}-linux-server-lan"
  }
}
# Associate routing table with subnets
resource "aws_route_table_association" "winserv"{
    subnet_id = "${aws_subnet.windows-servers.id}"
    route_table_id = "${aws_route_table.main.id}"
}
resource "aws_route_table_association" "linserv"{
    subnet_id = "${aws_subnet.linux-servers.id}"
    route_table_id = "${aws_route_table.main.id}"
}

############################################################
# Firewall Rule Setup
############################################################
resource "aws_security_group" "firewallsetup" {
    vpc_id = "${aws_vpc.main.id}"
    egress {
        from_port = 0
        to_port = 0
        protocol = -1
        cidr_blocks = ["0.0.0.0/0"]
    }
    ingress {
        from_port = 22
        to_port = 22
        protocol = "tcp"
        cidr_blocks = ["${local.public_ip}/32"]
    }
    ingress {
        from_port = 3389
        to_port = 3389
        protocol = "tcp"
        cidr_blocks = ["${local.public_ip}/32"]
    }
    ingress {
        from_port = 445
        to_port = 445
        protocol = "tcp"
        cidr_blocks = ["${local.public_ip}/32"]
    }
    ingress {
        from_port = 5985
        to_port = 5985
        protocol = "tcp"
        cidr_blocks = ["${local.public_ip}/32"]
    }
    ingress {
        from_port = 5986
        to_port = 5986
        protocol = "tcp"
        cidr_blocks = ["${local.public_ip}/32"]
    }
    
  tags = {
    Name = "${var.prefix}-firewall"
  }
}

############################################################
# Key Creation & Credential Setup
############################################################

resource "tls_private_key" "deploykey" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "generated_key" {
  key_name   = "${var.prefix}-deploykey"
  public_key = tls_private_key.deploykey.public_key_openssh
}

data "template_file" "win_creds" {
template = <<EOF
<script> netsh advfirewall set allprofiles state off
</script>
<powershell>
$url = "https://raw.githubusercontent.com/ansible/ansible/devel/examples/scripts/ConfigureRemotingForAnsible.ps1"
$file = "$env:SystemDrive\ConfigureRemotingForAnsible.ps1"
(New-Object -TypeName System.Net.WebClient).DownloadFile($url, $file)
powershell.exe -ExecutionPolicy ByPass -File $file
Enable-PSRemoting -force
$account = [ADSI]("WinNT://localhost/Administrator,user")
$account.psbase.invoke("setpassword","${local.config_file.local_admin_credentials.password}")
</powershell>
<persist>false</persist>
EOF 
}

############################################################
# Linux Server Resources
############################################################

resource "aws_instance" "linux-servers" {
  depends_on                  = [aws_internet_gateway.gw, aws_key_pair.generated_key,aws_security_group.firewallsetup]
  count                       = length(local.config_file.linux_server_configuration)
  ami                         = local.config_file.linux_server_configuration[count.index].ami
  availability_zone           = var.region
  instance_type               = local.config_file.linux_server_configuration[count.index].size
  monitoring                  = true
  vpc_security_group_ids      = [aws_security_group.firewallsetup.id]
  subnet_id                   = "${aws_subnet.linux-servers.id}"
  associate_public_ip_address = true
  key_name                    = aws_key_pair.generated_key.key_name
  
  root_block_device {
    volume_size = "100" 
    volume_type = "standard"
    delete_on_termination = "true"
  }
     
  tags = {
    Name  = local.config_file.linux_server_configuration[count.index].name
    amireference = local.config_file.linux_server_configuration[count.index].ami
    kind = "os.lab-linux-server"
    os = local.config_file.linux_server_configuration[count.index].os
    username = local.config_file.linux_server_configuration[count.index].username
  }
}

############################################################
# Windows Server Resources
############################################################

resource "aws_instance" "windows-servers" {
  depends_on                  = [aws_internet_gateway.gw, aws_key_pair.generated_key,aws_security_group.firewallsetup]
  count                       = length(local.config_file.windows_server_configuration)
  ami                         = local.config_file.windows_server_configuration[count.index].ami
  availability_zone           = var.region
  instance_type               = local.config_file.windows_server_configuration[count.index].size
  monitoring                  = true
  vpc_security_group_ids      = [aws_security_group.firewallsetup.id]
  subnet_id                   = "${aws_subnet.windows-servers.id}"
  associate_public_ip_address = true
  get_password_data           = true
  key_name                    = aws_key_pair.generated_key.key_name
  user_data                   = data.template_file.win_creds.rendered
  
  root_block_device {
    volume_size = "100" 
    volume_type = "standard"
    delete_on_termination = "true"
  }
     
  tags = {
    Name  = local.config_file.windows_server_configuration[count.index].name
    amireference = local.config_file.windows_server_configuration[count.index].ami
    kind = "os.lab-windows-server"
    os = local.config_file.windows_server_configuration[count.index].os
  }
}

############################################################
# Outputs
############################################################

output "printout" {
depends_on = [aws_internet_gateway.gw, aws_key_pair.generated_key,aws_security_group.firewallsetup,aws_instance.windows-servers,aws_instance.linux-servers]
value = <<EOF
Network Setup:

Windows Servers:
  %{ for index, x in aws_instance.windows-servers.* ~}
  External IP : ${x.public_ip} OS: ${x.tags_all["Name"]}
  %{ endfor }

Unix/Linux Servers:
  %{ for index, x in aws_instance.linux-servers.* ~}
  External IP : ${x.public_ip} OS: ${x.tags_all["Name"]}
  %{ endfor }

Remote Access:
  RDP to Windows Workstation:
  %{ for index, x in aws_instance.windows-servers.* ~}
  xfreerdp /v:${x.public_ip} /u:Administrator '/p:${local.config_file.local_admin_credentials.password}' +clipboard /cert-ignore
  %{ endfor }

  SSH to Linux Servers: 
  %{ for index, x in aws_instance.linux-servers.* ~}
  ssh -o StrictHostKeyChecking=accept-new ${x.tags_all["username"]}@${x.public_ip} -i sshkey.openssh
  %{ endfor }  
  
Credentials:
  Local Admin on Windows Servers: 
    Username: Administrator 
    Password: ${local.config_file.local_admin_credentials.password}
  Linux SSH login key (randomly generated, save in file):
    Username: See above for specific username.
    SSH Key: 

${nonsensitive(tls_private_key.deploykey.private_key_pem)}

EOF
}
