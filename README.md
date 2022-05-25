# OS.LAB

<p align="center">
  <img src="https://github.com/op7ic/OS.LAB/blob/main/documentation/pic/logo.PNG?raw=true" alt="OS.LAB"/>
</p>

# Purpose

This project contains a set of **Terraform** scripts to create an lab with different versions of popular operating systems. The goal of this project is to provide red/blue teams, developers and IT teams with the ability to deploy a ad-hoc OS lab to test attacks, payload operability, compatbility of tools and forensic artifacts on various versions of operating systems with minimal overhead.

**NOTE**: This lab is deliberately designed to be insecure. Please do not connect this system to any network you care about. 

**NOTE**: Cloud providers typically limit the number of IPs, CPUs and other resources for each subscription. You might need to open up an support ticker to extend quota to deploy complete lab. Please visit specific vendor help pages to see what kind of limits are applied on the account or regions - [Azure](https://docs.microsoft.com/en-us/azure/azure-portal/supportability/quotas-overview) and [AWS](https://docs.aws.amazon.com/general/latest/gr/aws_service_limits.html).

---

# Prerequisites for Azure

A number of features need to be installed on your system in order to use this setup. Please follow steps below to ensure that CLI and API required by Azure/AWS are fully functional before deployment.

```
# Step 1 - Install Azure CLI. More details on https://docs.microsoft.com/en-us/cli/azure/install-azure-cli-linux?pivots=apt
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# Step 2 - Install Terraform. More details on https://learn.hashicorp.com/tutorials/terraform/install-cli
sudo apt-get update && sudo apt-get install -y gnupg software-properties-common curl
curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
sudo apt-get update && sudo apt-get install terraform

# Step 3 - Install Ansible. More details on https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html
sudo apt update
sudo apt install software-properties-common
sudo add-apt-repository --yes --update ppa:ansible/ansible
sudo apt update
sudo apt install ansible

# Step 4 - Finally install python and various packages needed for remote connections and other activities
sudo apt install python3 python3-pip
pip3 install pywinrm requests msrest msrestazure azure-cli
```

# Prerequisites for AWS
```
# Step 1 - Install AWS CLI. More details on https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# Step 2 - Install Terraform. More details on https://learn.hashicorp.com/tutorials/terraform/install-cli
sudo apt-get update && sudo apt-get install -y gnupg software-properties-common curl
curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
sudo apt-get update && sudo apt-get install terraform

# Step 3 - Install Ansible. More details on https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html
sudo apt update
sudo apt install software-properties-common
sudo add-apt-repository --yes --update ppa:ansible/ansible
sudo apt update
sudo apt install ansible

# Step 4 - Finally install python and various packages needed for remote connections and other activities
sudo apt install python3 python3-pip pywinrm requests
```

# Building and Deploying OS.LAB

Once all the [prerequisites](#prerequisites-for-azure) are installed, perform the following series of steps:
```
# Log in to Azure or AWS from command line to ensure that the access token is valid or credentials are added for AWS:
az login or use aws configure 

# Clone Repository and move to BlueTeam.Lab folder:
git clone https://github.com/op7ic/OS.Lab.git
cd OS.Lab/azure # or cd OS.Lab/aws

# Initialize Terraform and begin planning:
terraform init && terraform plan

# Create your lab using the following command: 
terraform apply -auto-approve

# Once done, destroy your lab using the following command:
terraform destroy -auto-approve

# If you would like to time the execution us following command:
start_time=`date +%s` && terraform apply -auto-approve && end_time=`date +%s` && echo execution time was `expr $end_time - $start_time` s
```

# Deploying different OS versions or limiting number of created hosts

A global YAML config file, [Azure os-setup.yml](azure/config/os-setup.yml) or [AWS os-setup.yml](aws/config/os-setup.yml), set the type of operating system, SKU, AMI and VM size used for the deployment of individual VMs. 

Commands ```az vm image list``` (Azure) or ```aws ec2 describe-images``` (AWS) can be used to identify various OS versions so that global operating system file ([Azure os-setup.yml](azure/config/os-setup.yml) or [AWS os-setup.yml](aws/config/os-setup.yml) can be modified with correspodning SKU or AMI. Examples of commands helping to identify specific AMI/SKU can be found below.

```
# Azure

# List all Windows workstation SKUs and images
az vm image list --publisher MicrosoftWindowsDesktop --all -o table
# List all Windows servers SKUs and images
az vm image list --publisher WindowsServer --all -o table
# List all Debian servers SKUs and images
az vm image list --publisher Debian --all -o table
# List all RedHat servers SKUs and images
az vm image list --publisher RedHat --all -o table
# List all Canonical servers SKUs and images
az vm image list --publisher Canonical --all -o table

# AWS

# List all Windows Server AMIs
aws ec2 describe-images --owners amazon --filters Name=root-device-type,Values=ebs Name=architecture,Values=x86_64 Name=name,Values=*Windows_Server*English*Base* --query 'Images[].{ID:ImageId,Name:Name,Created:CreationDate}' --region us-east-1
# List all RedHat Server AMIs
aws ec2 describe-images --owners 309956199498 --query 'sort_by(Images, &CreationDate)[*].[CreationDate,Name,ImageId]' --filters "Name=name,Values=RHEL-*" --region us-east-1 --output table
# List all Ubuntu Server AMIs or use https://cloud-images.ubuntu.com/locator/ec2/
aws ec2 describe-images --filters Name=architecture,Values=x86_64 Name=name,Values=*Ubuntu* --query 'Images[].{ID:ImageId,Name:Name,Created:CreationDate}' --region us-east-1
# List all CentOS Server AMIs or use https://wiki.centos.org/Cloud/AWS
aws ec2 describe-images --filters Name=architecture,Values=x86_64 Name=name,Values=*CentOS* --query 'Images[].{ID:ImageId,Name:Name,Created:CreationDate}' --region us-east-1
# List all Debian Server AMIs or use https://wiki.debian.org/Amazon%20EC2
aws ec2 describe-images --filters Name=architecture,Values=x86_64 Name=name,Values=*Debian* --query 'Images[].{ID:ImageId,Name:Name,Created:CreationDate}' --region us-east-1
```

Please note that Windows desktop (i.e. Windows 10/11) are currently not supported on AWS EC2 without building a custom AMI so AWS version of OS.Lab does not support its deployment as it relies on pre-existing images. That said, [AWS os-setup.yml](aws/os-setup.yml) can be easily modified to include reference to custom AMIs.

# Changing network ranges and deployment location

Location and network ranges can be set using global variables in [Azure variables.tf](azure/variables.tf) or [AWS variables.tf](aws/variables.tf) file. A simple modification to runtime variables also allows to specify regions or network ranges as seen below:

```
# Use default options for Azure or AWS
terraform apply -auto-approve

# Use East US region to deploy the lab for Azure
terraform apply -auto-approve -var="region=East US"

# Use East US region to deploy the lab for AWS
terraform apply -auto-approve -var="region=us-east-1a"

# Use East US and change Windows/Linux server ranges for Azure
terraform apply -auto-approve -var="region=East US" -var="windows_server_subnet_cidr=10.0.0.0/24" -var="linux_server_subnet_cidr=10.100.0.0/24"

# Use East US and change Windows/Linux server ranges for AWS
terraform apply -auto-approve -var="region=us-east-1a" -var="windows_server_subnet_cidr=10.0.0.0/24" -var="linux_server_subnet_cidr=10.100.0.0/24"
```

---
# Firewall Configuration

The following table summarises a set of firewall rules applied across the OS.LAB enviroment in default configuration. Please modify the [azure main.tf](azure/main.tf) or [azure main.tf](aws/main.tf) file to add new firewall rules as needed in  the **Firewall Rule Setup** section. 

| Rule Name | Network Security Group | Source Host | Source Port  | Destination Host | Destination Port |
| ------------- | ------------- |  ------------- |  ------------- |  ------------- |  ------------- |
| Allow-RDP  | windows-nsg  | [Your Public IP](https://ipinfo.io/json) | * | Windows Servers, Windows Desktops  | 3389 |  
| Allow-WinRM  | windows-nsg  | [Your Public IP](https://ipinfo.io/json) | * | PWindows Servers, Windows Desktops | 5985 |  
| Allow-WinRM-secure | windows-nsg  | [Your Public IP](https://ipinfo.io/json) | * | Windows Servers, Windows Desktops | 5986 |  
| Allow-SMB  | windows-nsg  | [Your Public IP](https://ipinfo.io/json) | * | Windows Servers, Windows Desktops | 445 |
| Allow-SSH  |  linux-servers-nsg| [Your Public IP](https://ipinfo.io/json) | * | Linux Servers| 22 |  

Internally the following static IP ranges are used for this enviroment in the default configuration:

| Hosts  | Internal IP range | Notes | 
| ------------- | ------------- | ------------- |
| Windows Servers | 10.0.10.0/24 | |
| Windows Desktop  | 10.0.12.0/24 | N/A for AWS |
| Linux Servers | 10.0.11.0/24 | |

---
# Terraform Output - AWS

Once OS.LAB is constructed, Terraform will print out actual location of the systems and associated credentials. An example output from AWS Terraform execution can be found below.

```
Network Setup:

Windows Servers:
	External IP : xxx.xxx.xxx.xxx OS: Server 2012
	External IP : xxx.xxx.xxx.xxx OS: Server 2012R2
	External IP : xxx.xxx.xxx.xxx OS: Server 2016
	External IP : xxx.xxx.xxx.xxx OS: Server 2019
	External IP : xxx.xxx.xxx.xxx OS: Server 2022


Unix/Linux Servers:
	External IP : xxx.xxx.xxx.xxx OS: Debian 11
	External IP : xxx.xxx.xxx.xxx OS: Debian 10
	External IP : xxx.xxx.xxx.xxx OS: Debian 9
	External IP : xxx.xxx.xxx.xxx OS: CentOS Linux 8
	External IP : xxx.xxx.xxx.xxx OS: CentOS Linux 7
	External IP : xxx.xxx.xxx.xxx OS: Ubuntu 12.04 LTS
	External IP : xxx.xxx.xxx.xxx OS: Ubuntu 14.04 LTS
	External IP : xxx.xxx.xxx.xxx OS: Ubuntu 16.04 LTS
	External IP : xxx.xxx.xxx.xxx OS: Ubuntu 18.04 LTS
	External IP : xxx.xxx.xxx.xxx OS: Ubuntu 19.04
	External IP : xxx.xxx.xxx.xxx OS: Ubuntu 20.04 LTS
	External IP : xxx.xxx.xxx.xxx OS: Red Hat 6.1 x86_64
	External IP : xxx.xxx.xxx.xxx OS: Red Hat 6.1 i386
	External IP : xxx.xxx.xxx.xxx OS: Red Hat 6.10 x86_64
	External IP : xxx.xxx.xxx.xxx OS: Red Hat 7.9
	External IP : xxx.xxx.xxx.xxx OS: Red Hat 8.6 x86_64


Remote Access:
  RDP to Windows Workstation:
	xfreerdp /v:xxx.xxx.xxx.xxx /u:Administrator '/p:OsLabTesting0%%%' +clipboard /cert-ignore
	[...]


  SSH to Linux Servers:
	ssh -o StrictHostKeyChecking=accept-new admin@xxx.xxx.xxx.xxx -i sshkey.openssh
	ssh -o StrictHostKeyChecking=accept-new admin@xxx.xxx.xxx.xxx -i sshkey.openssh
	ssh -o StrictHostKeyChecking=accept-new admin@xxx.xxx.xxx.xxx -i sshkey.openssh
	[...]


Credentials:
  Local Admin on Windows Servers:
	Username: Administrator
	Password: OsLabTesting0%%%
  Linux SSH login key (randomly generated, save in file):
	Username: See above for specific username.
	SSH Key:

-----BEGIN RSA PRIVATE KEY-----
[...]
-----END RSA PRIVATE KEY-----
```

# Terraform Output - Azure

Once OS.LAB is constructed, Terraform will print out actual location of the systems and associated credentials. An example output from Azure Terraform execution can be found below.

```
Network Setup:
  Windows Workstations:
	External IP : xxx.xxx.xxx.xxx, OS : Windows11
	External IP : xxx.xxx.xxx.xxx , OS : Windows10
	External IP : xxx.xxx.xxx.xxx , OS : Windows7

  Windows Servers:
	External IP : xxx.xxx.xxx.xxx , OS : 2008Server
	External IP : xxx.xxx.xxx.xxx , OS : 2012DataCen
	External IP : xxx.xxx.xxx.xxx , OS : 2012R2DataCen
	External IP : xxx.xxx.xxx.xxx , OS : 2016DataCen
	External IP : xxx.xxx.xxx.xxx , OS : 2019DataCen
	External IP : xxx.xxx.xxx.xxx , OS : 2022DataCen

  Linux Servers:
	External IP : xxx.xxx.xxx.xxx , OS : Debian10
	External IP : xxx.xxx.xxx.xxx , OS : Debian11
	External IP : xxx.xxx.xxx.xxx , OS : DebianSid
	External IP : xxx.xxx.xxx.xxx , OS : RHEL-6.10
	External IP : xxx.xxx.xxx.xxx , OS : RHEL-7.2
	External IP : xxx.xxx.xxx.xxx , OS : RHEL-7.3
	External IP : xxx.xxx.xxx.xxx , OS : RHEL-7.4
	External IP : xxx.xxx.xxx.xxx , OS : RHEL-7.5
	External IP : xxx.xxx.xxx.xxx , OS : RHEL-7.6
	External IP : xxx.xxx.xxx.xxx , OS : RHEL-7.7
	External IP : xxx.xxx.xxx.xxx , OS : RHEL-7.8
	External IP : xxx.xxx.xxx.xxx , OS : RHEL-7.9
	External IP : xxx.xxx.xxx.xxx , OS : RHEL-8
	External IP : xxx.xxx.xxx.xxx , OS : RHEL-8.1
	External IP : xxx.xxx.xxx.xxx , OS : RHEL-8.2
	External IP : xxx.xxx.xxx.xxx , OS : RHEL-8.3
	External IP : xxx.xxx.xxx.xxx , OS : RHEL-8.4
	External IP : xxx.xxx.xxx.xxx , OS : RHEL-8.5
	External IP : xxx.xxx.xxx.xxx , OS : Ubuntu-12.04.3-LTS
	External IP : xxx.xxx.xxx.xxx , OS : Ubuntu-14.04.0-LTS
	External IP : xxx.xxx.xxx.xxx , OS : Ubuntu-16.04-LTS
	External IP : xxx.xxx.xxx.xxx , OS : Ubuntu-18.04-LTS
	External IP : xxx.xxx.xxx.xxx , OS : Ubuntu-19.04

Remote Access:
  RDP to Windows Workstation:
	xfreerdp /v:xxx.xxx.xxx.xxx /u:oslab '/p:OsLabTesting0%%%' +clipboard /cert-ignore
    [...]

  RDP to Windows Server:
	xfreerdp /v:xxx.xxx.xxx.xxx /u:oslab '/p:OsLabTesting0%%%' +clipboard /cert-ignore
	[...]

  SSH to Linux Servers:
	ssh -o StrictHostKeyChecking=accept-new oslab@xxx.xxx.xxx.xxx
    [...]
	
Credentials:
  Local Admin on Workstations and Windows Servers:
	oslab OsLabTesting0%%%
  Linux SSH Login:
	oslab OsLabTesting0%%%
```

# Contributing

Contributions, fixes, and improvements can be submitted directly for this project as a GitHub issue or a pull request.


