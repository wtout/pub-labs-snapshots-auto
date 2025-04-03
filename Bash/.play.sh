source "$(dirname "${0}")/common_parameters.sh"

# Main
PID="${$}"
stat=($(</proc/${PID}/stat))
INVOKERPID=${stat[3]}
DELRDOS=$(echo "${@}" | sed 's|&>/dev/null||' | xargs)
set -- && set -- "${@}" "${DELRDOS}"
check_arguments "${@}"
NEW_ARGS=$(check_hosts_limit "${@}")
set -- && set -- "${@}" "${NEW_ARGS}"
ORIG_ARGS="${@}"
ENAME=$(get_envname "${ORIG_ARGS}")
check_repeat_job && echo -e "\nRunning multiple instances of ${BOLD}$(basename "${0}")${NORMAL} is prohibited. Aborting!\n\n" && exit 1
INVENTORY_PATH="inventories/${ENAME}"
SYS_DEF="Definitions/${ENAME}.yml"
SYS_ALL="${INVENTORY_PATH}/group_vars/all.yml"
SVCVAULT="vars/.svc_acct_creds_${ENAME}.yml"
CONTAINERNAME="$(whoami | cut -d '@' -f1)_${ENAME}"
NEW_ARGS=$(clean_arguments '--envname' "${ENAME}" "${@}")
check_deffile
set -- && set -- "${@}" "${NEW_ARGS}"
for cnum in {1..3}
do
	check_container "${CONTAINERNAME}_${cnum}" && kill_container "${CONTAINERNAME}_${cnum}"
done
# Phase 1
start_container "${CONTAINERNAME}_1"
[[ $- =~ x ]] && debug=1 && [[ "${SECON}" == "true" ]] && set +x
chmod 644 "${PASSVAULT}"
PCREDS_LIST=$(get_creds "${CONTAINERNAME}_1" primary)
PROXY_ADDRESS=$(get_proxy) || PA=${?}
[[ ${PA} -eq 1 ]] && echo -e "\n${PROXY_ADDRESS}\n" && exit ${PA}
[[ ${debug} == 1 ]] && set -x
[[ $- =~ x ]] && debug=1 && [[ "${SECON}" == "true" ]] && set +x
rm -f "${SVCVAULT}"; umask 0022; touch "${SVCVAULT}"
[[ "$(echo ${PCREDS_LIST})" != "" ]] && echo "${PCREDS_LIST[@]}" | sed "s/$(get_creds_prefix primary)/P/g; s/^\(.*: \)\(.*\)$/\1'\2'/g" >> "${SVCVAULT}" || PCREDS_EMPTY=true
[[ ${PCREDS_EMPTY} ]] && echo "Service creds not found" && Exit 1
[[ ${debug} == 1 ]] && set -x
add_write_permission "${SVCVAULT}"
encrypt_vault "${CONTAINERNAME}_1" "${SVCVAULT}" Bash/get_common_vault_pass.sh
sudo chown "$(stat -c '%U' "$(pwd)")":"$(stat -c '%G' "$(pwd)")" "${SVCVAULT}"
sudo chmod 644 "${SVCVAULT}"
get_inventory "${CONTAINERNAME}_1" "${@}"
get_hosts "${CONTAINERNAME}_1" "${@}"
NUM_HOSTSINPLAY=$([[ "$(get_hostsinplay "${CONTAINERNAME}_1" "${HL}" | wc -w)" != "0" ]] && get_hostsinplay "${CONTAINERNAME}_1" "${HL}" | wc -w || echo "1")
kill_container "${CONTAINERNAME}_1"
# Phase 2
enable_logging "${CONTAINERNAME}_2" "${@}"
start_container "${CONTAINERNAME}_2"
run_playbook "${CONTAINERNAME}_2" "${@}"
kill_container "${CONTAINERNAME}_2"
disable_logging
# Phase 3
start_container "${CONTAINERNAME}_3"
send_notification "${CONTAINERNAME}_3" "${ORIG_ARGS}"
kill_container "${CONTAINERNAME}_3"
exit ${SCRIPT_STATUS}
