# README #

This README provides instructions and information to get your Linux utility machine up and running with the automation package to delete old VM snapshots.


### What is this repository for? ###

This repository contains Ansible playbooks to be used in the removal of VM snapshots from VCenter.


### Disclaimer ###

The deployment procedure has to be the same for all deployments. Ansible code contained in this repository is to automate the standard deployment procedure. Customization for a given deployment is limited to the environment variables used during installation. Do not modify the Ansible code on the fly during installation. Ansible code is NOT meant to be touched/edited except in the context of standard deployment procedure automation development. The usage information below gives the user the needed information to set up and execute the supported automated procedures.


### Installation ###

On a newly installed Linux **CentOS 7.7+/AlmaLinux8+** VM that has docker installed and configured and that can access the internet, container repo and the VM infrastructure, run the following command to download and start the container hosting the automation code:

1- Install the git package

    $> sudo yum install -y git

6- Download the Ansible automation package

    $> git clone https://github.com/wtout/pub-labs-snapshots-auto.git

7- Go to the newly cloned pub-labs-linux-auto directory

    $> cd pub-labs-snapshots-auto

***Note**: you might need to disable the proxy to be able to clone the repository*


### System definition ###

Create your own system definition file under the _``Definitions``_ directory to contain the datacenter name. Use the included _``build_def_info.yml``_ file as a template

***Note**: If you choose to make changes to git tracked items such as directory names or file names or content of files downloaded from the repository, be aware that your changes will be lost every time the automated installation package is updated*

The system definition file consists of the following variables:

  - **datacenter.primary.name** (_String_): Required. Primary Datacenter name
  - **datacenter.primary.max_snapshot_age** (_Integer_): Required. Snapshots maximum age
  - **datacenter.primary.vm_age** (_Integer_): Required. Virtual Machine age

To create the system inventory without deploying the system, issue the following command from the automation root directory (pub-labs-snapshots-auto):

    $> bash Bash/play_deploy.sh --envname <system-name> --tags none


### System Deployment ###

1- From the automation root directory (pub-labs-snapshots-auto), run the bash script under the Bash directory.

    $> bash Bash/play_deploy.sh --envname <system-name>

with the _``system-name``_ being the name of the system definition file from "System Definition"

The Script output is automatically saved to a log file. The file is saved under _``Logs/<script-name>.<system-name>.log.<time-stamp>``_ on the Linux utility machine

***Note**: Running multiple instances of the same script for a given build simultaneously is prohibited*

2- Answer the prompts on the CLI. If you simply hit enter, default values will be used unless an input is required. In such a case you will be prompted again to enter a value


### Roles ###

The list of roles used in the playbooks:

  - **define_inventory**: generates the system inventory from the system definition file
  - **check_creds**: validates the user's credentials
  - **remove_snapshots**: removes VM snapshots older than defined max_snapshot_age
  - **decomm_vm**: moves a VM to the decommissioning list if it is older than a defined vm_age and it is not tagged
  - **remove_decomm**: removes VMs on or after the date-todecomm date
  - **print_stats**: prints statistics gathered during the execution of the different roles
  - **notify**: sends a notification via Webex Teams channel indicating the status of the activity


### Who do I talk to? ###

* Repo owner or admin
