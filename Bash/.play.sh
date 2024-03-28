source $(dirname "${0}")/functions_library.sh

# Parameters definition
ANSIBLE_CFG="ansible.cfg"
ANSIBLE_LOG_LOCATION="Logs"
BOLD=$(tput bold)
NORMAL=$(tput sgr0)
ANSIBLE_VERSION='8.7.0'
ANSIBLE_VARS="vars/datacenters.yml"
PASSVAULT="vars/passwords.yml"
REPOVAULT="vars/.repovault.yml"
CONTAINERWD="/home/ansible/$(basename ${PWD})"
CONTAINERREPO="containers.cisco.com/watout/ansible"

# Main
PID="${$}"
stat=($(</proc/${PID}/stat))
INVOKERPID=${stat[3]}
add_user_uid_gid
add_user_docker_group
[[ "$(get_os)" == "AlmaLinux"* || "$(get_os)" == "Ubuntu"* ]] && [[ "$($(docker_cmd) images|grep -vi tag)" == "" ]] && podman system migrate
create_dir "${ANSIBLE_LOG_LOCATION}"
DELRDOS=$(echo "${@}" | sed 's|&>/dev/null||' | xargs)
set -- && set -- "${@}" "${DELRDOS}"
check_arguments "${@}"
check_docker_login
restart_docker
NEW_ARGS=$(check_hosts_limit "${@}")
set -- && set -- "${@}" "${NEW_ARGS}"
ORIG_ARGS="${@}"
ENAME=$(get_envname "${ORIG_ARGS}")
check_repeat_job && echo -e "\nRunning multiple instances of ${BOLD}$(basename "${0}")${NORMAL} is prohibited. Aborting!\n\n" && exit 1
INVENTORY_PATH="inventories/${ENAME}"
SYS_DEF="Definitions/${ENAME}.yml"
SYS_ALL="${INVENTORY_PATH}/group_vars/all.yml"
SVCVAULT="vars/.svc_acct_creds_${ENAME}.yml"
CONTAINERNAME="$(whoami | cut -d '@' -f1)_ansible_${ANSIBLE_VERSION}_${ENAME}"
NEW_ARGS=$(clean_arguments '--envname' "${ENAME}" "${@}")
check_deffile
set -- && set -- "${@}" "${NEW_ARGS}"
git_config
SECON=$([[ "$(git config user.email|cut -d '@' -f1)" == "watout" ]] && echo "false" || echo "true")
for cnum in {1..3}
do
	check_container "${CONTAINERNAME}_${cnum}" && kill_container "${CONTAINERNAME}_${cnum}" &>/dev/null
done
image_prune
start_container "${CONTAINERNAME}_1" &>/dev/null
[[ $- =~ x ]] && debug=1 && [[ "${SECON}" == "true" ]] && set +x
chmod 644 "${PASSVAULT}"
PCREDS_LIST=$(get_creds "${CONTAINERNAME}_1" primary)
PROXY_ADDRESS=$(get_proxy) || PA=${?}
[[ ${PA} -eq 1 ]] && echo -e "\n${PROXY_ADDRESS}\n" && exit ${PA}
[[ ${debug} == 1 ]] && set -x
add_write_permission ${PWD}/vars
if [[ -z ${MYINVOKER+x} ]]
then
	get_repo_creds "${REPOVAULT}" Bash/get_repo_vault_pass.sh
	check_updates "${CONTAINERNAME}_1" "${REPOVAULT}" Bash/get_repo_vault_pass.sh
	CHECK_UPDATE_STATUS=${?}
else
	CHECK_UPDATE_STATUS=0
fi
if [[ ${CHECK_UPDATE_STATUS} -eq 3 ]]
then
	kill_container "${CONTAINERNAME}_1" &>/dev/null
	exit 1
else
	[[ $- =~ x ]] && debug=1 && [[ "${SECON}" == "true" ]] && set +x
	rm -f "${SVCVAULT}"; umask 0022; touch "${SVCVAULT}"
	[[ "$(echo ${PCREDS_LIST})" != "" ]] && echo "${PCREDS_LIST[@]}" | sed "s/$(get_creds_prefix primary)/P/g; s/^\(.*: \)\(.*\)$/\1'\2'/g" >> "${SVCVAULT}"
	[[ ${debug} == 1 ]] && set -x
	add_write_permission "${SVCVAULT}"
	encrypt_vault "${CONTAINERNAME}_1" "${SVCVAULT}" Bash/get_common_vault_pass.sh
	sudo chown "$(stat -c '%U' "$(pwd)")":"$(stat -c '%G' "$(pwd)")" "${SVCVAULT}"
	sudo chmod 644 "${SVCVAULT}"
	get_inventory "${CONTAINERNAME}_1" "${@}"
	get_hosts "${CONTAINERNAME}_1" "${@}"
	NUM_HOSTSINPLAY=$([[ "$(get_hostsinplay "${CONTAINERNAME}_1" "${HL}" | wc -w)" != "0" ]] && get_hostsinplay "${CONTAINERNAME}_1" "${HL}" | wc -w || echo "1")
	add_write_permission "${PWD}/roles"
	add_write_permission "${PWD}/roles/*"
	add_write_permission "${PWD}/roles/*/files"
	enable_logging "${CONTAINERNAME}_2" "${@}"
	start_container "${CONTAINERNAME}_2" &>/dev/null
	kill_container "${CONTAINERNAME}_1" &>/dev/null
	run_playbook "${CONTAINERNAME}_2" "${@}"
	disable_logging
	start_container "${CONTAINERNAME}_3" &>/dev/null
	kill_container "${CONTAINERNAME}_2" &>/dev/null
	send_notification "${CONTAINERNAME}_3" "${ORIG_ARGS}"
	kill_container "${CONTAINERNAME}_3" &>/dev/null
	exit ${SCRIPT_STATUS}
fi
