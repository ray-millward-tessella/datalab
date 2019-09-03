# Provisioning

This document describes how to create and use Ansible control environment.
A number of tools are used in this process including VirtualBox, Vagrant and Ansible.

The current development environment is CentOS 7 and instructions have only
been tested in this environment.

## Machine setup

### Install VirtualBox

Instructions followed from [here](https://wiki.centos.org/HowTos/Virtualization/VirtualBox)

Add the repo

```bash
cd /etc/yum.repos.d
wget http://download.virtualbox.org/virtualbox/rpm/rhel/virtualbox.repo
```

Install DKMS (Dynamic Kernel Module Support)

`yum --enablerepo=epel install dkms`

Search for available packages and install the selected version

```bash
yum search VirtualBox
sudo yum install VirtualBox-5.1.x86_64
```

### Install Vagrant

Download from the [Vagrant](https://www.vagrantup.com/downloads.html) website.

Install using ```rpm```

`sudo yum install <package-name>.rpm`

### Create Ansible control VM

Create the Ansible control VM by executing ```vagrant up``` in
the ```code/provision``` directory.

## Using Ansible control VM

SSH onto the ansible control machine using ```vagrant ssh```.

Start an SSH agent to avoid having to continually supply the SSH key password.

```bash
ssh-agent bash
ssh-add ~/keys/<ssh_key>
```

Check that Ansible is correctly provisioned by executing

`ansible <host> -m ping -u <user>`

where ```user``` is the user to connect as. This will be ```root``` for new
machines but initial provisioning will add a new ```deploy``` user and remove
the root access.

## Executing Ansible scripts

Note that server locations may change and the inventory may need to be updated
prior to execution until we have dynamic inventory

### New Server

This combines scripts in order:

* Notify Slack for start
* Secure Server
* Base Configuration

### Secure Server (secure-server.yml)

The secure server script currently targets any servers in the insecure
inventory group. Once they have been secured they should be moved. While
ansible is idempotent the script currently executes as the root user and
its last step is to remove root SSH. This means that a second execution
is unable to connect. This is still a work in progress.

To execute:

`~/playbooks$ ansible-playbook --ssh-common-args="-o StrictHostKeyChecking=no" secure-server.yml`

### Base Configuration (base-configuration.yml)

This playbook:

* Installs some core packages
* Configures SSH firewall rules
* Installs and configures logwatch and postfix

To execute:

`~/playbooks$ ansible-playbook base-configuration.yml`