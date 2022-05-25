##########################################################
# Author      : Jerzy 'Yuri' Kramarz (op7ic)             #
# Version     : 1.0                                      #
# Type        : Terraform                                #
# Description : OS.LAB. See README.md for details        # 
##########################################################


############################################################
# Provider And Resource Group Definition
############################################################

# Azure Provider source and version being used
terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "=2.46.0"
    }
  }
}

# Configure the Microsoft Azure Provider
provider "azurerm" {
  features {}
}

# Create resource group
# Note that all deployment relies on this resource group so we set manual "depends_on" everywhere
resource "azurerm_resource_group" "resourcegroup" {
  location            = var.region
  name                = var.resource_group
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
# Networking Setup - Internal
############################################################

# Define primary network range (10.0.0.0/16)
resource "azurerm_virtual_network" "main" {
  depends_on = [azurerm_resource_group.resourcegroup]
  name                = "${var.prefix}-network"
  address_space       = ["10.0.0.0/16"]
  location            = var.region
  resource_group_name = var.resource_group
}

# Define LAN for Windows Servers
resource "azurerm_subnet" "windows-servers" {
  depends_on = [azurerm_resource_group.resourcegroup]
  name                 = "windows-servers-subnet"
  resource_group_name  = var.resource_group
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [var.windows_server_subnet_cidr]
}

# Define LAN for Linux Servers
resource "azurerm_subnet" "linux-servers" {
  depends_on = [azurerm_resource_group.resourcegroup]
  name                 = "linux-servers-subnet"
  resource_group_name  = var.resource_group
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [var.linux_server_subnet_cidr]
}

# Define LAN for Workstations
resource "azurerm_subnet" "windows-workstations" {
  depends_on = [azurerm_resource_group.resourcegroup]
  name                 = "windows-workstations-subnet"
  resource_group_name  = var.resource_group
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [var.windows_workstations_subnet_cidr]
}


############################################################
# Networking Setup - External
############################################################

resource "azurerm_public_ip" "linux-servers" {
  count                   = length(local.config_file.linux_server_configuration)
  depends_on = [azurerm_resource_group.resourcegroup]
  name                    = "${var.prefix}-LINUX-${count.index}-ingress"
  location                = var.region
  resource_group_name     = var.resource_group
  allocation_method       = "Static"
  idle_timeout_in_minutes = 30
}

resource "azurerm_public_ip" "windows-workstations" {
  depends_on = [azurerm_resource_group.resourcegroup]
  count                   = length(local.config_file.windows_workstation_configuration)
  name                    = "${var.prefix}-WIN-WRK-${count.index}-ingress"
  location                = var.region
  resource_group_name     = var.resource_group
  allocation_method       = "Static"
  idle_timeout_in_minutes = 30
}

resource "azurerm_public_ip" "windows-servers" {
  count                   = length(local.config_file.windows_server_configuration)
  depends_on = [azurerm_resource_group.resourcegroup]
  name                    = "${var.prefix}-WIN-SRV-${count.index}-ingress"
  location                = var.region
  resource_group_name     = var.resource_group
  allocation_method       = "Static"
  idle_timeout_in_minutes = 30
}

############################################################
# Firewall Rule Setup
############################################################

resource "azurerm_network_security_group" "windows" {
  depends_on = [azurerm_resource_group.resourcegroup]
  name                = "windows-nsg"
  location            = var.region
  resource_group_name = var.resource_group

  security_rule {
    name                       = "Allow-RDP"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "${local.public_ip}/32"
    destination_address_prefix = "*"
  }
  
  security_rule {
    name                       = "Allow-WinRM"
    priority                   = 101
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "5985"
    source_address_prefix      = "${local.public_ip}/32"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "Allow-WinRM-secure"
    priority                   = 102
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "5986"
    source_address_prefix      = "${local.public_ip}/32"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "Allow-SMB"
    priority                   = 103
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "445"
    source_address_prefix      = "${local.public_ip}/32"
    destination_address_prefix = "*"
  }
}

resource "azurerm_network_security_group" "linux" {
  depends_on = [azurerm_resource_group.resourcegroup]
  name                = "linux-servers-nsg"
  location            = var.region
  resource_group_name = var.resource_group

  security_rule {
    name                       = "Allow-SSH"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "${local.public_ip}/32"
    destination_address_prefix = "*"
  }
}
############################################################
# Linux Server Resources
############################################################
# Create IP address space and interface for our Linux Servers 
# Use count as parameter to pass to resources since we are creating multiple systems
resource "azurerm_network_interface" "linux" {
  depends_on = [azurerm_resource_group.resourcegroup]
  count = length(local.config_file.linux_server_configuration)
  name                = "${var.prefix}-LINUX-${count.index}-nic"
  location              = var.region
  resource_group_name   = var.resource_group

  ip_configuration {
    name                          = "static"
    subnet_id                     = azurerm_subnet.linux-servers.id
    private_ip_address_allocation = "Static"
    private_ip_address = cidrhost(var.linux_server_subnet_cidr, 100+count.index)
    public_ip_address_id = azurerm_public_ip.linux-servers[count.index].id
  }
  
  tags = {
     name = local.config_file.linux_server_configuration[count.index].name
     externalIP = azurerm_public_ip.linux-servers[count.index].ip_address
     sku = local.config_file.linux_server_configuration[count.index].sku     
  }
}
# Associate IP and Security Group with our Linux Servers
resource "azurerm_network_interface_security_group_association" "linux" {
  depends_on = [azurerm_resource_group.resourcegroup]
  count = length(local.config_file.linux_server_configuration)
  network_interface_id      = azurerm_network_interface.linux[count.index].id
  network_security_group_id = azurerm_network_security_group.linux.id
}
# Create Linux Servers
resource "azurerm_virtual_machine" "linux-server" {
  count = length(local.config_file.linux_server_configuration)
  name                  = local.config_file.linux_server_configuration[count.index].name
  location              = var.region
  resource_group_name   = var.resource_group
  network_interface_ids = [azurerm_network_interface.linux[count.index].id]
  vm_size               = local.config_file.linux_server_configuration[count.index].vmsize
  
  # Apply tag to our workstations. We use this to dynamically identify IP addresses.
  tags = {
    kind = "os.lab-linux-server"
  }
  
  # Delete OS disk automatically when deleting the VM
  delete_os_disk_on_termination = true
  # Delete data disks automatically when deleting the VM
  delete_data_disks_on_termination = true

  storage_image_reference {
    publisher = local.config_file.linux_server_configuration[count.index].publisher
    offer     = local.config_file.linux_server_configuration[count.index].os
    sku       = local.config_file.linux_server_configuration[count.index].sku
    version   = "latest"
  }
  
  storage_os_disk {
    name              = "${var.prefix}-LINUX-${count.index}-os-disk"
    caching           = "ReadWrite"
    create_option     = "FromImage"
    managed_disk_type = "Standard_LRS"
  }
  
  os_profile {
    computer_name  = local.config_file.linux_server_configuration[count.index].name
    admin_username = local.config_file.local_admin_credentials.username
    admin_password = local.config_file.local_admin_credentials.password
  }
  
  # we use password authentication here for ease of operation
  os_profile_linux_config {
    disable_password_authentication = false
  }
  
}# EOF Linux Server Setup

############################################################
# Workstations Resources
############################################################
# Create IP address space and interface for our workstations 
# Use count as parameter to pass to resources since we are creating multiple systems
resource "azurerm_network_interface" "workstation" {
  depends_on = [azurerm_resource_group.resourcegroup]
  count = length(local.config_file.windows_workstation_configuration)
  name                = "${var.prefix}-WIN-WRK-${count.index}-nic"
  location              = var.region
  resource_group_name   = var.resource_group

  ip_configuration {
    name                          = "static"
    subnet_id                     = azurerm_subnet.windows-workstations.id
    private_ip_address_allocation = "Static"
    private_ip_address = cidrhost(var.windows_workstations_subnet_cidr, 100+count.index)
    public_ip_address_id = azurerm_public_ip.windows-workstations[count.index].id
  }
    tags = {
     name = local.config_file.windows_workstation_configuration[count.index].name
     externalIP = azurerm_public_ip.windows-workstations[count.index].ip_address
     sku = local.config_file.windows_workstation_configuration[count.index].sku
  }
}
# Associate IP and Security Group with our workstations
resource "azurerm_network_interface_security_group_association" "workstation" {
  depends_on = [azurerm_resource_group.resourcegroup]
  count = length(local.config_file.windows_workstation_configuration)
  network_interface_id      = azurerm_network_interface.workstation[count.index].id
  network_security_group_id = azurerm_network_security_group.windows.id
}

# Create workstations based on our setup
resource "azurerm_virtual_machine" "workstation" {

  count = length(local.config_file.windows_workstation_configuration)
  name                  = local.config_file.windows_workstation_configuration[count.index].name
  location              = var.region
  resource_group_name   = var.resource_group
  network_interface_ids = [azurerm_network_interface.workstation[count.index].id]
  vm_size               = local.config_file.windows_workstation_configuration[count.index].vmsize
  
  # Apply tag to our workstations. We use this to dynamically identify IP addresses.
  tags = {
    kind = "os.lab-windows-workstation"
  }

  # Delete OS disk automatically when deleting the VM
  delete_os_disk_on_termination = true

  # Delete data disks automatically when deleting the VM
  delete_data_disks_on_termination = true

  storage_image_reference {
    publisher = local.config_file.windows_workstation_configuration[count.index].publisher
    offer     = local.config_file.windows_workstation_configuration[count.index].os
    sku       = local.config_file.windows_workstation_configuration[count.index].sku
    version   = "latest"
  }
  
  storage_os_disk {
    name              = "${var.prefix}-WIN-WRK-${count.index}-os-disk"
    caching           = "ReadWrite"
    create_option     = "FromImage"
    managed_disk_type = "Standard_LRS"
  }
  
  os_profile {
    computer_name  = local.config_file.windows_workstation_configuration[count.index].os
    admin_username = local.config_file.local_admin_credentials.username
    admin_password = local.config_file.local_admin_credentials.password
  }
  os_profile_windows_config {
      provision_vm_agent = true
      enable_automatic_upgrades = false
      timezone = "Central European Standard Time"
      winrm {
        protocol = "HTTP"
      }
  }
  
}# EOF Workstation Setup

############################################################
# Windows Server Resources
############################################################
# Create IP address space and interface for Windows servers 
# Use count as parameter to pass to resources since we are creating multiple systems
resource "azurerm_network_interface" "winserver" {
  depends_on = [azurerm_resource_group.resourcegroup]
  count = length(local.config_file.windows_server_configuration)
  name                = "${var.prefix}-WIN-SRV-${count.index}-nic"
  location              = var.region
  resource_group_name   = var.resource_group

  ip_configuration {
    name                          = "static"
    subnet_id                     = azurerm_subnet.windows-servers.id
    private_ip_address_allocation = "Static"
    private_ip_address = cidrhost(var.windows_server_subnet_cidr, 100+count.index)
    public_ip_address_id = azurerm_public_ip.windows-servers[count.index].id
  }
    tags = {
     name = local.config_file.windows_server_configuration[count.index].name
     externalIP = azurerm_public_ip.windows-servers[count.index].ip_address
     sku = local.config_file.windows_server_configuration[count.index].sku
  }
}
# Associate IP and Security Group with Windows Servers
resource "azurerm_network_interface_security_group_association" "winserver" {
  depends_on = [azurerm_resource_group.resourcegroup]
  count = length(local.config_file.windows_server_configuration)
  network_interface_id      = azurerm_network_interface.winserver[count.index].id
  network_security_group_id = azurerm_network_security_group.windows.id
}


# Create windows servers based on our setup
resource "azurerm_virtual_machine" "winservers" {

  count = length(local.config_file.windows_server_configuration)
  name                  = local.config_file.windows_server_configuration[count.index].name
  location              = var.region
  resource_group_name   = var.resource_group
  network_interface_ids = [azurerm_network_interface.winserver[count.index].id]
  vm_size               = local.config_file.windows_server_configuration[count.index].vmsize
  
  # Apply tag to our workstations. We use this to dynamically identify IP addresses.
  tags = {
    kind = "os.lab-windows-server"
  }

  # Delete OS disk automatically when deleting the VM
  delete_os_disk_on_termination = true

  # Delete data disks automatically when deleting the VM
  delete_data_disks_on_termination = true

  storage_image_reference {
    publisher = local.config_file.windows_server_configuration[count.index].publisher
    offer     = local.config_file.windows_server_configuration[count.index].os
    sku       = local.config_file.windows_server_configuration[count.index].sku
    version   = "latest"
  }
  
  storage_os_disk {
    name              = "${var.prefix}-WIN-SRV-${count.index}-os-disk"
    caching           = "ReadWrite"
    create_option     = "FromImage"
    managed_disk_type = "Standard_LRS"
  }
  
  os_profile {
    computer_name  = local.config_file.windows_server_configuration[count.index].os
    admin_username = local.config_file.local_admin_credentials.username
    admin_password = local.config_file.local_admin_credentials.password
  }
  os_profile_windows_config {
      provision_vm_agent = true
      enable_automatic_upgrades = false
      timezone = "Central European Standard Time"
      winrm {
        protocol = "HTTP"
      }
  }
  
}# EOF Windows Server Setup


############################################################
# Outputs
############################################################

output "printout" {
depends_on = [azurerm_resource_group.resourcegroup, azurerm_network_interface.workstation, azurerm_network_interface.linux, azurerm_network_interface.winserver]
  value = <<EOF

Network Setup:
  Windows Workstations:
  %{ for index, x in azurerm_network_interface.workstation.* ~}
  External IP: ${x.tags["externalIP"]} OS: ${x.tags["name"]}
  %{ endfor }
  
  Windows Servers:
  %{ for index, x in azurerm_network_interface.winserver.* ~}
  External IP: ${x.tags["externalIP"]} OS: ${x.tags["name"]}
  %{ endfor }

  Linux Servers:
  %{ for index, x in azurerm_network_interface.linux.* ~}
  External IP: ${x.tags["externalIP"]} OS: ${x.tags["name"]}
  %{ endfor }
  
Remote Access:
  RDP to Windows Workstation:
  %{ for index, ip in azurerm_public_ip.windows-workstations.*.ip_address ~}
  xfreerdp /v:${ip} /u:${local.config_file.local_admin_credentials.username} '/p:${local.config_file.local_admin_credentials.password}' +clipboard /cert-ignore
  %{ endfor }

  RDP to Windows Server:
  %{ for index, ip in azurerm_public_ip.windows-servers.*.ip_address ~}
  xfreerdp /v:${ip} /u:${local.config_file.local_admin_credentials.username} '/p:${local.config_file.local_admin_credentials.password}' +clipboard /cert-ignore
  %{ endfor }

  SSH to Linux Servers: 
  %{ for index, ip in azurerm_public_ip.linux-servers.*.ip_address ~}
  ssh -o StrictHostKeyChecking=accept-new ${local.config_file.local_admin_credentials.username}@${ip}  
  %{ endfor }
  

Credentials:
  Local Admin on Workstations and Windows Servers: 
    ${local.config_file.local_admin_credentials.username} ${local.config_file.local_admin_credentials.password}
  Linux SSH Login:
    ${local.config_file.local_admin_credentials.username} ${local.config_file.local_admin_credentials.password}

EOF
}
