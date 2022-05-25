############################################################
# Defualt config for various settings such as LAN segments, location of domain config file etc.
############################################################

variable "system_config_file" {
    description = "Path to the primary configuration file for deployment"
    default = "config/os-setup.yml"
}

variable "windows_server_subnet_cidr" {
    description = "CIDR to use for hosting Windows Servers"
    default = "10.0.10.0/24"
}

variable "linux_server_subnet_cidr" {
    description = "CIDR to use for hosting Linux/Debian/Ubuntu Servers"
    default = "10.0.11.0/24"
}

variable "region" {
    description = "AWS region in which resources should be created. See https://aws.amazon.com/about-aws/global-infrastructure/regions_az/"
    default = "us-east-1a"
}

variable "resource_group" {
    description = "Resource group in which resources should be created"
    default = "os-lab"
}

variable "prefix" {
    description = "prefix for dynamic hosts"
    default = "os-lab"
}

