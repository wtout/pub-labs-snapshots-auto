source $(dirname "${0}")/functions_library.sh

# Parameters definition
ANSIBLE_CFG="ansible.cfg"
ANSIBLE_LOG_LOCATION="Logs"
BOLD=$(tput bold)
NORMAL=$(tput sgr0)
ANSIBLE_VERSION='9.4.0'
ANSIBLE_VARS="vars/datacenters.yml"
PASSVAULT="vars/passwords.yml"
REPOVAULT="vars/.repovault.yml"
CONTAINERWD="/home/ansible/$(basename ${PWD})"
CONTAINERREPO="containers.cisco.com/watout/ansible"
SECON=$([[ "$(git config --file .git/config user.email|cut -d '@' -f1)" == "watout" ]] && echo "false" || echo "true")

