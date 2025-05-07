source $(dirname "${0}")/common_parameters.sh

# Main
PID="${$}"
[[ $- =~ x ]] && BASHOPTION='-x '
ORIG_ARGS="${@}"
ENV_LIST=$(get_envname_list "${ORIG_ARGS}")
NEW_ARGS=$(clean_arguments '--envname' "${ENV_LIST}" "${ORIG_ARGS}" | xargs)
LOOP_LIST=(${ENV_LIST//,/ })
ENV_LIST_LENGTH=$(echo "${ENV_LIST//,/ }" | wc -w)
SCRIPT_NAME=$(echo "${0}" | sed 's|play_||')

###############################################
CONTAINERNAME="$(whoami | cut -d '@' -f1)_$(basename ${PWD})"
add_user_uid_gid
add_user_docker_group
[[ "$(get_os)" == "AlmaLinux"* || "$(get_os)" == "Ubuntu"* ]] && [[ "$($(docker_cmd) images|grep -vi tag)" == "" ]] && $(docker_cmd) system migrate
create_dir "${ANSIBLE_LOG_LOCATION}"
check_docker_login
restart_docker
git_config
[[ "$(git config --file .git/config user.name|cut -d ' ' -f2 | tr '[:upper:]' '[:lower:]')" == "tout" ]] && image_prune
pull_image
check_container "${CONTAINERNAME}" && kill_container "${CONTAINERNAME}"
start_container "${CONTAINERNAME}"
add_write_permission "${PWD}/vars"
add_write_permission "${PWD}/roles"
add_write_permission "$(find "${PWD}/roles" -type d -name files -exec dirname {} \;)"
find "${PWD}/roles" -type d -name files -exec chmod 757 {} \;
get_repo_creds "${CONTAINERNAME}" "${REPOVAULT}" Bash/get_repo_vault_pass.sh
get_secrets_vault "${CONTAINERNAME}" "${REPOVAULT}" Bash/get_repo_vault_pass.sh
if [[ -z ${MYINVOKER+x} ]]
then
	check_updates "${CONTAINERNAME}" "${REPOVAULT}" Bash/get_repo_vault_pass.sh
	CHECK_UPDATE_STATUS=${?}
else
	CHECK_UPDATE_STATUS=0
fi
kill_container "${CONTAINERNAME}"
if [[ ${CHECK_UPDATE_STATUS} -eq 3 ]]
then
	exit 3
else
###############################################
	BGPIDS=""
	AC=0
	[[ "${ENV_LIST_LENGTH}" -gt 1 ]] && echo
	for i in "${!LOOP_LIST[@]}"
	do
		[[ "${i}" -gt 0 ]] && sleep "${i}"
		if [[ "${ENV_LIST_LENGTH}" -gt 1 ]]
		then
			[[ ${BASHOPTION} =~ x ]] && NOHUP_DEST="${LOOP_LIST[i]}.out" || NOHUP_DEST="/dev/null"
			nohup bash ${BASHOPTION}${SCRIPT_NAME} --envname "${LOOP_LIST[i]}" "${NEW_ARGS}" &>"${NOHUP_DEST}" &
			BGPIDS+=" ${!}"
			echo "Executing: bash ${BASHOPTION}${SCRIPT_NAME} --envname "${LOOP_LIST[i]}" "${NEW_ARGS}" &>"${NOHUP_DEST}" &"
		else
			bash ${BASHOPTION}${SCRIPT_NAME} --envname "${LOOP_LIST[i]}" "${NEW_ARGS}" &
			BGPIDS+=" ${!}"
		fi
	done
	[[ "${ENV_LIST_LENGTH}" -gt 1 ]] && echo "Please wait..."
	BGPIDS_LIST=(${BGPIDS})
	trap "kill_sub_processes ${$}" INT SIGINT TERM SIGTERM EXIT
	while [[ ${#BGPIDS_LIST[@]} -ne 0 ]]
	do
		for i in "${!BGPIDS_LIST[@]}"
		do
			if [[ ! -d "/proc/${BGPIDS_LIST[i]}" ]]
			then
				wait "${BGPIDS_LIST[i]}"
				EC="${?}"
				if [[ "${EC}" -ne 0 ]]
				then
					[[ "${ENV_LIST_LENGTH}" -gt 1 ]] && echo "System ${LOOP_LIST[i]} failed with exit code ${EC}"
				fi
				[[ "${AC}" -eq 0 ]] && AC="${EC}"
				unset BGPIDS_LIST[i]
			fi
		done
		sleep 2
	done
	# Clean up
	remove_secrets_vault
	remove_write_permission "${PWD}/vars"
	remove_write_permission "${PWD}/roles"
	find "${PWD}/roles" -type d -exec chmod 755 {} \;
	exit "${AC}"
fi
