source $(dirname "${0}")/functions_library.sh

# Parameters definition
ANSIBLE_CFG="ansible.cfg"
ANSIBLE_LOG_LOCATION="Logs"
BOLD=$(tput bold)
NORMAL=$(tput sgr0)
ANSIBLE_VERSION='11.1.0'
ANSIBLE_VARS="vars/datacenters.yml"
PASSVAULT="vars/passwords.yml"
REPOVAULT="vars/.repovault.yml"
CONTAINERWD="/home/ansible/$(basename ${PWD})"
CONTAINERREPO="registry-1.docker.io/wtout/ansible"
SECON=$([[ "$(git config --file .git/config user.name|cut -d ' ' -f2 | tr '[:upper:]' '[:lower:]')" == "tout" ]] && echo "false" || echo "true")
