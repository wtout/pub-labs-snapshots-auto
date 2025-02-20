# Functions declaration

function kill_sub_processes() {
	local pid
	local and_self
	local children
	pid="${1}"
	and_self="${2:-false}"
	if children=($(pgrep -P "${pid}"))
	then
		for child in "${children[@]}"
		do
			kill_sub_processes "${child}" true
		done
	fi
	if [[ "${and_self}" == true ]]
	then
		[[ "$(ps -o pid | grep ${pid})" != "" ]] && kill -9 "${pid}"
	fi
}

function create_dir() {
	if [[ ! -d "${1}" ]]
	then
		mkdir -m 775 -p "${1}"
		chown -R "$(stat -c '%U' "$(pwd)")":"$(stat -c '%G' "$(pwd)")" "${1}"
	else
		if [[ ! -w "${1}" ]]
		then
			chmod 775 "${1}"
			chown -R "$(stat -c '%U' "$(pwd)")":"$(stat -c '%G' "$(pwd)")" "${1}"
		fi
	fi
}

function get_envname_list() {
	local ENVLIST
	[[ "$(echo "${@}" | grep -Ew '\-\-envname')" != "" ]] && ENVLIST="$(echo "${@}" | awk -F 'envname ' '{print $NF}' | cut -d'-' -f1 | xargs)"
	echo "${ENVLIST}"
}

function get_envname() {
	local envname
	[[ "$(echo "${@}" | grep -Ew '\-\-envname')" != "" ]] && envname="$(echo "${@}" | awk -F 'envname ' '{print $NF}' | cut -d'-' -f1 | xargs)"
	echo "${envname}"
}

function check_arguments() {
	if [[ "$(echo "${@}" | grep -Ew '\-\-envname')" == "" ]]
	then
		printf "\nEnvironment name is required!\nRe-run the script with %s--envname%s <environment name as defined under Inventories>\n\n" "${BOLD}" "${NORMAL}"
		exit 1
	else
		[[ $(wc -w <<< "$(get_envname "${@}")") -ge 2 ]] && printf "\nYou can deploy only one environment at a time. Aborting!\n\n" && exit 1
		[[ $(wc -w <<< "$(get_envname "${@}")") -lt 1 ]] && printf "\nYou need to specify at least one environment. Aborting!\n\n" && exit 1
	fi
}

function check_deffile() {
	if [[ ! -f ${SYS_DEF} ]]
	then
		echo -e "\n${BOLD}System definition file for ${ENAME} cannot be found. Aborting!${NORMAL}"
		exit 1
	fi
}

function get_os() {
	local MYRELEASE
	MYRELEASE=$(grep ^NAME= /etc/os-release|cut -d '"' -f2|awk '{print $1}')
	if [[ "${MYRELEASE}" != "" ]]	
	then
		echo ${MYRELEASE}
		return 0
	else
		return 1
	fi
}

function add_user_uid_gid() {
	local MYID
	MYID=$(whoami)
	if [[ "$(id ${MYID} | grep 'domain users')" != '' ]]
	then
		grep ${MYID} /etc/subuid &>/dev/null || echo -e "${MYID}:$(expr $(tail -1 /etc/subuid|cut -d ':' -f2) + $(tail -1 /etc/subuid|cut -d ':' -f3)):$(tail -1 /etc/subuid|cut -d ':' -f3)" | sudo tee -a /etc/subuid 1>/dev/null
		yes|sudo cp -p /etc/subuid /etc/subgid
	fi
}

function add_user_docker_group() {
	local MYID
	MYID=$(whoami)
	if [[ "$(get_os)" == "CentOS"* ]] && [[ "$(id ${MYID} | grep 'domain users')" != '' ]]
	then
		if [[ "$(groups | grep docker)" == "" ]]
		then
			sudo usermod -aG docker ${MYID}
			echo -e "\n\n${BOLD}The ${MYID} user got added to the docker group. Please log out and log back in so that your group membership is re-evaluated${NORMAL}\n"
			exit 1
		fi
	fi
}

function check_docker_login() {
	local MYRELEASE
	local MYDOMAIN
	local MYJSONFILE
	local AUTHFILE
	local LOGGEDIN
	LOGGEDIN=true
	AUTHFILE1=${HOME}/.docker/config.json
	AUTHFILE2=${HOME}/.podman/auth.json
	MYDOMAIN=$(echo ${CONTAINERREPO}|cut -d '/' -f1)
	MYRELEASE=$(get_os)
	case ${MYRELEASE} in
		CentOS*)
			MYJSONFILE=${AUTHFILE1}
			;;
		AlmaLinux*)
			MYJSONFILE=${XDG_RUNTIME_DIR}/containers/auth.json
			;;
		Ubuntu*)
			MYJSONFILE=${AUTHFILE2}
			;;
		*)
			;;
	esac
	if [[ ${MYJSONFILE} == ${AUTHFILE1} ]]
	then
		if [[ ! -f ${MYJSONFILE} || "$(grep ${MYDOMAIN} ${MYJSONFILE})" == "" ]]
		then
			LOGGEDIN=false
		fi
	else
		if [[ -z ${REGISTRY_AUTH_FILE+x} ]]
		then
			if [[ ! -f ${AUTHFILE1} || "$(grep ${MYDOMAIN} ${AUTHFILE1})" == "" ]] && [[ ! -f ${AUTHFILE2} || "$(grep ${MYDOMAIN} ${AUTHFILE2})" == "" ]] && [[ ! -f ${MYJSONFILE} || "$(grep ${MYDOMAIN} ${MYJSONFILE})" == "" ]]
			then
				LOGGEDIN=false
			fi
		else
			if [[ ! -f ${REGISTRY_AUTH_FILE} ]]
			then
				unset REGISTRY_AUTH_FILE
				LOGGEDIN=false
			else
				[[ $(podman login --get-login ${MYDOMAIN} &>/dev/null; echo "${?}") -ne 0 ]] && [[ $(podman login --get-login ${MYDOMAIN} --authfile ${AUTHFILE2} &>/dev/null; echo "${?}") -ne 0 ]] && LOGGEDIN=false
			fi
		fi
	fi
	if [[ "${LOGGEDIN}" == "false" ]]
	then
		if [[ $(check_image; echo "${?}") -ne 0 ]]
		then
			echo -e "\nYou must login to ${MYDOMAIN} to gain access to images before running this automation"
			exit 1
		else
			echo -e "\nYou must login to ${MYDOMAIN} to gain access to automation images"
		fi
	fi
}

function docker_cmd() {
	local MYRELEASE
	MYRELEASE=$(get_os)
	case ${MYRELEASE} in
		CentOS*)
			if [[ -f /etc/systemd/system/docker@.service ]]
			then
				echo "docker -H unix:///var/run/docker-$(whoami).sock"
			else
				echo "docker"
			fi
			;;
		AlmaLinux*|Ubuntu*)
			echo "podman"
			;;
		*)
			;;
	esac
}

function restart_docker() {
	if [[ -f /etc/systemd/system/docker@.service ]]
	then
		if [[ "$($(docker_cmd) system info 2>/dev/null | grep -i containers | awk '{print $NF}')" == "0" ]]
		then
			sudo systemctl restart docker@$(whoami).service
		fi
	fi
}

function image_prune() {
	local CIID
	local IIDLIST
	CIID=$($(docker_cmd) images | grep -E "${CONTAINERREPO}.*${ANSIBLE_VERSION}" | awk '{print $3}')
	[[ "${CIID}" == "" ]] && IIDLIST=$($(docker_cmd) images -a -q) || IIDLIST=$($(docker_cmd) images -a -q | grep -v ${CIID})
	[[ "${IIDLIST}" != "" ]] && $(docker_cmd) rmi ${IIDLIST} -f
}

function check_image() {
	$(docker_cmd) images | grep -E "${CONTAINERREPO}.*${ANSIBLE_VERSION}" &>/dev/null
	return ${?}
}

function pull_image() {
	if [[ ! $(check_image) ]]
	then
		local MYRELEASE
		MYRELEASE=$(get_os)
		case ${MYRELEASE} in
			CentOS*)
				$(docker_cmd) pull "${CONTAINERREPO}:${ANSIBLE_VERSION}" &>"${ANSIBLE_LOG_LOCATION}"/"${PID}"-pull_error.stderr
				;;
			AlmaLinux*)
				if [[ -f ${HOME}/.podman/auth.json ]]
				then
					$(docker_cmd) pull "${CONTAINERREPO}:${ANSIBLE_VERSION}" --authfile ${HOME}/.podman/auth.json &>"${ANSIBLE_LOG_LOCATION}"/"${PID}"-pull_error.stderr
				else
					$(docker_cmd) pull "${CONTAINERREPO}:${ANSIBLE_VERSION}" --authfile ${XDG_RUNTIME_DIR}/containers/auth.json &>"${ANSIBLE_LOG_LOCATION}"/"${PID}"-pull_error.stderr
				fi
				;;
			Ubuntu*)
				$(docker_cmd) pull "${CONTAINERREPO}:${ANSIBLE_VERSION}" --authfile ${HOME}/.podman/auth.json &>"${ANSIBLE_LOG_LOCATION}"/"${PID}"-pull_error.stderr
				;;
			*)
				;;
		esac
		[[ $(grep -i "error" "${ANSIBLE_LOG_LOCATION}"/"${PID}"-pull_error.stderr) != "" ]] &>/dev/null && cat "${ANSIBLE_LOG_LOCATION}"/"${PID}"-pull_error.stderr && echo -e "\nCheck if the container image ${BOLD}${CONTAINERREPO}:${ANSIBLE_VERSION}${NORMAL} exists\n" && exit 1
		rm -f "${ANSIBLE_LOG_LOCATION}"/"${PID}"-pull_error.stderr
	fi
}

function check_container() {
	local CNTNRNAME
	CNTNRNAME="${1}"
	$(docker_cmd) ps -a | grep -w "${CNTNRNAME}" &>/dev/null
	return ${?}
}

function start_container() {
	local CNTNRNAME
	CNTNRNAME="${1}"
	if [[ $(check_container "${CNTNRNAME}"; echo "${?}") -ne 0 ]]
	then
		[[ ! -d ${HOME}/.ssh ]] && mkdir ${HOME}/.ssh
		[[ $- =~ x ]] && debug=1 && echo "Starting container ${CNTNRNAME}"
		[[ $- =~ x ]] && debug=1 && [[ "${SECON}" == "true" ]] && set +x
		if [[ "${ANSIBLE_LOG_PATH}" == "" ]]
		then
			$(docker_cmd) run --rm -e MYPROXY=${PROXY_ADDRESS} -e MYHOME=${PWD} -e MYHOSTNAME=$(hostname) -e MYCONTAINERNAME=${CNTNRNAME} -e MYIP=$(get_host_ip) --user ansible -w ${CONTAINERWD} -v /data:/data:z -v /tmp:/tmp:z -v ${PWD}:${CONTAINERWD}:z --name ${CNTNRNAME} -t -d --entrypoint /bin/bash ${CONTAINERREPO}:${ANSIBLE_VERSION} 1>/dev/null
		else
			$(docker_cmd) run --rm -e ANSIBLE_LOG_PATH=${ANSIBLE_LOG_PATH} -e ANSIBLE_FORKS=${NUM_HOSTSINPLAY} -e MYPROXY=${PROXY_ADDRESS} -e MYHOME=${PWD} -e MYHOSTNAME=$(hostname) -e MYCONTAINERNAME=${CNTNRNAME} -e MYIP=$(get_host_ip) -e MYHOSTOS=$(get_os) --user ansible -w ${CONTAINERWD} -v /data:/data:z -v /tmp:/tmp:z -v ${HOME}/.ssh:/home/ansible/.ssh:z -v ${PWD}:${CONTAINERWD}:z --name ${CNTNRNAME} -t -d --entrypoint /bin/bash ${CONTAINERREPO}:${ANSIBLE_VERSION} 1>/dev/null
		fi
		[[ ${debug} == 1 ]] && set -x
		[[ $(check_container "${CNTNRNAME}"; echo "${?}") -ne 0 ]] && echo "Unable to start container ${CNTNRNAME}" && exit 1
	fi
}

function kill_container() {
	local CNTNRNAME
	local dc
	CNTNRNAME="${1}"
	dc=$(docker_cmd)
	if [[ $(check_container "${CNTNRNAME}"; echo "${?}") -eq 0 ]]
	then
		[[ $- =~ x ]] && debug=1 && echo "Killing container ${CNTNRNAME}"
		if [[ "${dc}" == "podman" ]]
		then
			${dc} container rm ${CNTNRNAME} &>/dev/null
		else
			${dc} kill ${CNTNRNAME} &>/dev/null
		fi
	fi
}

function check_repeat_job() {
	ps -ef | grep -w "${ENAME}" | grep "Bash/play_" | grep -vwE "${PID}|${INVOKERPID}|grep" | grep -vw 'cd'
	return ${?}
}

function check_hosts_limit() {
	local MYARGS
	local ARG_NAME
	local MYACTION
	local NEWARGS
	MYARGS=$(echo "${@}" | sed 's/,\(dr\)*vcenter//')
	[[ "$(echo "${MYARGS}" | grep -Ew '\-\-limit')" != "" ]] && [[ "$(echo "${MYARGS}" | grep 'vcenter')" == "" ]] && ARG_NAME="--limit" && MYACTION="add"
	[[ "$(echo "${MYARGS}" | grep -Ew '\-l')" != "" ]] && [[ "$(echo "${MYARGS}" | grep 'vcenter')" == "" ]] && ARG_NAME="-l" && MYACTION="add"
	if [[ ${MYACTION} == "add" ]]
	then
		local MYHOSTS
		local MYTAGS
		local UPDATE_ARGS
		local VCENTERS
		MYHOSTS=$(echo "${MYARGS}" | awk -F "${ARG_NAME} " '{print $NF}' | awk -F ' -' '{print $1}')
		[[ "$(echo "${MYARGS}" | grep -Ew '\-\-tags')" != "" ]] && MYTAGS=$(echo "${MYARGS}" | awk -F '--tags ' '{print $NF}' | awk -F ' -' '{print $1}')
		[[ "${MYTAGS}" == "" ]] && UPDATE_ARGS=1
		[[ "$(echo "${MYTAGS}" | grep -Ew 'vm_creation|capcheck')" != "" ]] && UPDATE_ARGS=1
		if [[ "$(echo "${MYHOSTS}" | grep 'dr')" == "" ]]
		then
			VCENTERS='vcenter'
		else
			if [[ "$(echo "${MYHOSTS}" | sed "s/,/\n/g" | grep -v 'dr')" == "" ]]
			then
				VCENTERS='drvcenter'
			else
				VCENTERS='vcenter,drvcenter'
			fi
		fi
		if [[ ${UPDATE_ARGS} -eq 1 ]]
		then
			NEWARGS=$(echo "${MYARGS}" | sed "s/${MYHOSTS}/${MYHOSTS},${VCENTERS}/")
		else
			NEWARGS="${MYARGS}"
		fi
	else
		NEWARGS="${MYARGS}"
	fi
	echo "${NEWARGS}"
}

function clean_arguments() {
	# Remove --envname argument from script arguments
	local OPTION_NAME
	local OPTION_ARG
	local NEWARGS
	OPTION_NAME="${1}"
	OPTION_ARG="${2}"
	NEWARGS="${3}"
	if [[ "$(echo "${NEWARGS}" | sed -n "/${OPTION_NAME}/p")" != "" ]]
	then
		shift
		NEWARGS=$(echo "${NEWARGS}" | sed "s/${OPTION_NAME} ${OPTION_ARG}//")
	else
		NEWARGS="${NEWARGS}"
	fi
	echo "${NEWARGS}"
}

function git_config() {
	if [[ "$(which git 2>/dev/null)" != "" ]]
	then
		local NAME
		local SURNAME
		local GIT_EMAIL_ADDRESS
		local EC
		if ! git config --file .git/config remote.origin.url &>/dev/null
		then
			echo "You are not authorized to use this automation. Aborting!"
			exit 1
		fi
		if [[ "$(git config --file .git/config user.name)" == "" ]]
		then
			IFS=' ' read -rp "Enter your full name [ENTER]: " NAME SURNAME
			if [[ "$(git config --file .git/config remote.origin.url | grep "\/\/.*@")" == "" ]]
			then
				git config --file .git/config user.name "${NAME} ${SURNAME}" || EC=1
			else
				[[ "${SURNAME}" != "" ]] && [[ "$(git config --file .git/config remote.origin.url | sed -e 's/.*\/\/\(.*\)@.*/\1/')" == *"$(echo ${SURNAME:0:5} | tr '[:upper:]' '[:lower:]')"* ]] && git config --file .git/config user.name "${NAME} ${SURNAME}" || EC=1
			fi
		fi
		[[ ${EC} -eq 1 ]] && echo "Invalid full name. Aborting!" && exit ${EC}
		if [[ "$(git config --file .git/config user.email)" == "" ]]
		then
			NAME=$(git config --file .git/config user.name | awk '{print $1}' | tr '[:upper:]' '[:lower:]')
			SURNAME=$(git config --file .git/config user.name | awk '{print $NF}' | tr '[:upper:]' '[:lower:]')
			read -rp "Enter your email address [ENTER]: " GIT_EMAIL_ADDRESS
			if [[ -z "$(echo "${GIT_EMAIL_ADDRESS}"|grep -E '<|>')" ]]
			then
				if [[ "$(git config --file .git/config remote.origin.url | grep "\/\/.*@")" == "" ]] && [[ -n "${GIT_EMAIL_ADDRESS}" ]] && ([[ "$(echo "${GIT_EMAIL_ADDRESS}" | cut -d '@' -f1)" == *"$(echo ${NAME:0:2} | tr '[:upper:]' '[:lower:]')"* ]] || [[ "$(echo "${GIT_EMAIL_ADDRESS}" | cut -d '@' -f1)" == *"$(echo ${NAME:0:1} | tr '[:upper:]' '[:lower:]')"* ]]) && [[ "$(echo "${GIT_EMAIL_ADDRESS}" | cut -d '@' -f1)" == *"$(echo ${SURNAME:0:5} | tr '[:upper:]' '[:lower:]')"* ]]
				then
					git config --file .git/config user.email "${GIT_EMAIL_ADDRESS}" && git config --file .git/config remote.origin.url "$(git config --file .git/config remote.origin.url | sed -e "s|//\(\w\)|//$(echo "${GIT_EMAIL_ADDRESS}" | cut -d '@' -f1)@\1|")" || EC=1
				else
					[[ "$(git config --file .git/config remote.origin.url)" == *"$(echo "${GIT_EMAIL_ADDRESS}" | cut -d '@' -f1)"* ]] && git config --file .git/config user.email "${GIT_EMAIL_ADDRESS}" || EC=1
				fi
			else
				git config --file .git/config user.email "${GIT_EMAIL_ADDRESS}" || EC=1
			fi
		fi
		[[ ${EC} -eq 1 ]] && echo "Invalid email address. Aborting!" && exit ${EC}
	else
		echo "Please ensure git is installed on this machine before running script. Aborting!" && exit 1
	fi
}

function get_proxy() {
	local MYPROXY
	local PUBLIC_ADDRESS
	chmod +x Bash/get*
	grep -r '^proxy.*:.*@*' /etc/environment /etc/profile /etc/profile.d/ ~/.bashrc ~/.bash_profile &>/dev/null && [[ $- =~ x ]] && debug=1 && [[ "${SECON}" == "true" ]] && set +x
	MYPROXY=$(grep -rh "^proxy.*=.*" /etc/environment /etc/profile /etc/profile.d/ ~/.bashrc ~/.bash_profile 2>/dev/null | cut -d '"' -f2 | uniq)
	[[ "${MYPROXY}" != "" ]] && [[ "$(echo "${MYPROXY}" | grep http)" == "" ]] && MYPROXY=http://${MYPROXY}
	PUBLIC_ADDRESS="https://time.google.com"
	if [[ "${MYPROXY}" == "" ]]
	then
		curl ${PUBLIC_ADDRESS} &>/dev/null
		if [[ ${?} -eq 0 ]]
		then
			echo "${MYPROXY}"
			return 0
		else
			echo -e "Unable to find proxy configuration in /etc/environment /etc/profile /etc/profile.d/ ~/.bashrc ~/.bash_profile. Aborting!\n"
			return 1
		fi
	else
		curl --proxy "${MYPROXY}" "${PUBLIC_ADDRESS}" &>/dev/null
		if [[ ${?} -eq 0 ]]
		then
			echo "${MYPROXY}"
			return 0
		else
			[[ $- =~ x ]] && debug=1 && [[ "${SECON}" == "true" ]] && set +x
			select_creds primary vcenter_service user "${PCREDS_LIST[@]}" 1>/dev/null && read -r PPUSER <<< "$(select_creds primary vcenter_service user "${PCREDS_LIST[@]}")"
			select_creds primary vcenter_service pass "${PCREDS_LIST[@]}" 1>/dev/null && read -r PPPASS <<< "$(select_creds primary vcenter_service pass "${PCREDS_LIST[@]}")"
			MYPROXY=$(echo "${MYPROXY}" | sed -e "s|//.*@|//|g" -e "s|//|//${PPUSER}:${PPPASS}@|g")
			curl --proxy "${MYPROXY}" "${PUBLIC_ADDRESS}" &>/dev/null
			if [[ ${?} -eq 0 ]]
			then
				echo "${MYPROXY}"
				return 0
			else
				if [[ -n "${SPUSER+x}" ]] && [[ -n "${SPPASS+x}" ]]
				then
					MYPROXY=$(echo "${MYPROXY}" | sed -e "s|//.*@|//|g" -e "s|//|//${SPUSER}:${SPPASS}@|g")
					curl --proxy "${MYPROXY}" "${PUBLIC_ADDRESS}" &>/dev/null
					if [[ ${?} -eq 0 ]]
					then
						echo "${MYPROXY}"
						return 0
					else
						[[ ${debug} == 1 ]] && debug=0 && set -x
						echo -e "Proxy credentials are not valid. Aborting!\n"
						return 1
					fi
				fi
			fi
		fi
	fi
}

function add_write_permission() {
	for i in ${*}
	do
		sudo chmod o+w ${i}
	done
}

function remove_write_permission() {
	for i in ${*}
	do
		sudo chmod o-w ${i}
	done
}

function get_creds_prefix() {
    local FILETOCHECK
    local DATACENTER
    local CREDS_PREFIX
	[[ -f "${SYS_DEF}" ]] && FILETOCHECK="${SYS_DEF}" || FILETOCHECK="${SYS_ALL}"
	DATACENTER=$(cat "${FILETOCHECK}" | sed "/^\s*$/d" | grep -A22 -P "^datacenter:$" | sed -n "/${1}:/,+2p" | sed -n "/name:/,1p" | awk -F ': ' '{print $NF}' | sed "s/'//g")
	if [[ "${?}" == "0" ]] && [[ "${DATACENTER}" != "" ]] && [[ "${DATACENTER}" != "''" ]]
	then
		case ${DATACENTER} in
			Alln1 | RTP5 | *Build*)
				CREDS_PREFIX='PROD_'
				;;
			RTP-Staging | STG*)
				CREDS_PREFIX='STG_'
				;;
			PAE-External)
				CREDS_PREFIX='PAEEXT_'
				;;
			*)
				CREDS_PREFIX='PAETEST_'
				;;
		esac
		echo ${CREDS_PREFIX}
		return 0
	else
		return 1
	fi
}

function get_creds() {
	local CNTNRNAME
	CNTNRNAME=${1}
	if [[ $(get_creds_prefix ${2}) ]]
	then
		view_vault "${CNTNRNAME}" "${PASSVAULT}" Bash/get_common_vault_pass.sh | grep ^$(get_creds_prefix ${2}) | sed "s/'//g"
		return 0
	else
		return 1
	fi
}

function select_creds() {
	local SITE
	local ACCT
	local CRED
	local CREDS_LIST
	SITE=${1}
	ACCT=${2}
	CRED=${3}
	shift; shift; shift
	CREDS_LIST=("${@}")
	if [[ "$(echo ${CREDS_LIST})" != '' ]]
	then
		echo "${CREDS_LIST[@]}" | grep ^$(get_creds_prefix ${SITE})${ACCT^^}_${CRED^^} | cut -d " " -f2
		return 0
	else
		return 1
	fi
}

function remove_hosts_arg() {
	# Remove --limit or -l argument from script arguments
	local ARG_NAME
	local MYACTION
	local NEWARGS
	[[ "$(echo "${@}" | grep -Ew '\-\-limit')" != "" ]] && ARG_NAME="--limit" && MYACTION="clean"
	[[ "$(echo "${@}" | grep -Ew '\-l')" != "" ]] && ARG_NAME="-l" && MYACTION="clean"
	if [[ ${MYACTION} == "clean" ]]
	then
		local MYARGS
		MYARGS=$(echo "${@}" | awk -F "${ARG_NAME} " '{print $NF}' | awk -F ' -' '{print $1}')
		NEWARGS=$(echo "${@}" | sed "s/${ARG_NAME} ${MYARGS}//")
	else
		NEWARGS="${@}"
	fi
	echo "${NEWARGS}"
}

function remove_extra_vars_arg() {
	local ARG_NAME
	local MYACTION
	local NEWARGS
	# Remove --extra-vars or -e argument from script arguments
	[[ "$(echo "${@}" | grep -Ew '\-\-extra\-vars')" != "" ]] && ARG_NAME="--extra-vars" && MYACTION="clean"
	[[ "$(echo "${@}" | grep -Ew '\-e')" != "" ]] && ARG_NAME="-e" && MYACTION="clean"
	if [[ ${MYACTION} == "clean" ]]
	then
		local MYARGS
		MYARGS=$(echo "${@}" | awk -F "${ARG_NAME} " '{print $NF}' | awk -F ' -' '{print $1}')
		NEWARGS=$(echo "${@}" | sed "s|${ARG_NAME} ${MYARGS}||")
	else
		NEWARGS="${@}"
	fi
	echo "${NEWARGS}"
}

function get_host_ip() {
	ip a show "$(ip link | grep 2: | head -1 | awk '{print $2}')" | grep 'inet ' | cut -d '/' -f1 | awk '{print $2}'
}

function encrypt_vault() {
	local CNTNRNAME
	CNTNRNAME="${1}"
	[[ -f ${2} ]] && [[ -f ${3} ]] && [[ -x ${3} ]] && $(docker_cmd) exec -i ${CNTNRNAME} ansible-vault encrypt "${2}" --vault-password-file "${3}" &>"${ANSIBLE_LOG_LOCATION}"/"${PID}"-encrypt_error.stderr
	if [[ -s "${ANSIBLE_LOG_LOCATION}"/"${PID}"-encrypt_error.stderr && "$(grep 'ERROR' "${ANSIBLE_LOG_LOCATION}"/"${PID}"-encrypt_error.stderr)" != "" ]]
	then
		cat "${ANSIBLE_LOG_LOCATION}"/"${PID}"-encrypt_error.stderr
		exit 1
	else
		rm "${ANSIBLE_LOG_LOCATION}"/"${PID}"-encrypt_error.stderr
	fi
}

function view_vault() {
	local CNTNRNAME
	CNTNRNAME="${1}"
	[[ -f ${2} ]] && [[ -f ${3} ]] && [[ -x ${3} ]] && $(docker_cmd) exec -i ${CNTNRNAME} ansible-vault view "${2}" --vault-password-file "${3}" 2>"${ANSIBLE_LOG_LOCATION}"/"${PID}"-decrypt_error.stderr
	[[ $(grep "was not found" "${ANSIBLE_LOG_LOCATION}"/"${PID}"-decrypt_error.stderr) != "" ]] && sed -i "/^vault_password_file.*$/,+d" "${ANSIBLE_CFG}" && $(docker_cmd) exec -i ${CNTNRNAME} ansible-vault view "${2}" --vault-password-file "${3}" &>/dev/null
	rm -f "${ANSIBLE_LOG_LOCATION}"/"${PID}"-decrypt_error.stderr
}

function get_repo_creds() {
	local REPOUSER
	local REPOPASS
	local CNTNRNAME
	CNTNRNAME="${1}"
	[[ -f ${2} ]] && grep 'REPOPASS=' "${2}" 1>/dev/null && rm -f "${2}"
	if [[ ! -f ${2} ]]
	then
		echo -e "\n\nYour ${BOLD}$(git config --file .git/config --get remote.origin.url|cut -d '/' -f3|cut -d '@' -f2)${NORMAL} Repository credentials are needed"
		read -rp "Enter your Repository username [ENTER]: " REPOUSER
		read -rsp "Enter your Repository token [ENTER]: " REPOPASS
		echo
		if [[ ${REPOUSER} != "" && ${REPOPASS} != "" ]]
		then
			[[ $- =~ x ]] && debug=1 && [[ "${SECON}" == "true" ]] && set +x
			printf "REPOUSER='%s'\nREPOPASS='%s'\n" "${REPOUSER}" "${REPOPASS}" > "${2}"
			add_write_permission "${2}"
			encrypt_vault "${1}" "${2}" "${3}"
			[[ ${debug} == 1 ]] && set -x
			sudo chown "$(stat -c '%U' "$(pwd)")":"$(stat -c '%G' "$(pwd)")" "${2}"
			sudo chmod 644 "${2}"
		else
			echo
			echo "Unable to get repo credentials"
			echo
			[[ -z ${MYINVOKER+x} ]] && kill_container "${CNTNRNAME}" && exit 1
		fi
	fi
}

function read_repo_cred() {
	local CNTNRNAME
	local REPOCRED
	CNTNRNAME="${1}"
	read -r REPOCRED <<< "$(view_vault "${CNTNRNAME}" "${2}" "${3}" | grep $(echo ${4//REPO/}) | cut -d "'" -f2)"
	echo "${REPOCRED}"
}

function get_secrets_vault() {
	if [[ ! -f ${PASSVAULT} ]]
	then
		local CNTNRNAME
		local REPOUSER
		local REPOPASS
		local REMOTEURL
		local localbranch
		local remotebranchlist
		CNTNRNAME="${1}"
		localbranch=$(git branch|grep '^*'|awk '{print $NF}')
		[[ -z ${localbranch} ]] && echo "Unable to determine the current branch. Exiting!" && exit 1
		remotebranchlist=$(git branch -r)
		if [[ $(echo ${remotebranchlist}|grep '/'${localbranch}) ]]
		then
			[[ $- =~ x ]] && debug=1 && [[ "${SECON}" == "true" ]] && set +x
			REPOUSER=$(read_repo_cred "${CNTNRNAME}" "${2}" "${3}" "REPOUSER")
			REPOPASS=$(read_repo_cred "${CNTNRNAME}" "${2}" "${3}" "REPOPASS")
			REPOPWD="${REPOPASS//@/%40}"
			[[ "$(git config --file .git/config --get remote.origin.url | grep '\/\/.*@')" == "" ]] && REMOTEURL=$(git config --file .git/config --get remote.origin.url | sed -e "s|//\(\w\)|//${REPOUSER}:${REPOPWD}@\1|") || REMOTEURL=$(git config --file .git/config --get remote.origin.url | sed -e "s|//.*@|//${REPOUSER}:${REPOPWD}@|")
			for i in {1..3}
			do
				git clone --branch ${localbranch} --single-branch "$(echo "${REMOTEURL}" | sed -e "s|pub-||" -e "s|auto|auto-secrets|")" .tmp &>"${ANSIBLE_LOG_LOCATION}"/"${PID}"-get-secrets-vault.stderr
				[[ ${?} -eq 0 ]] && break || CLONE_FAILED="true"
			done
			if [[ "${CLONE_FAILED}" ]]
			then
				[[ "$(grep 'Invalid username or password' "${ANSIBLE_LOG_LOCATION}"/"${PID}"-get-secrets-vault.stderr)" != '' ]] && rm -f "${REPOVAULT}"
				echo -e "${BOLD}Unable to download the secrets vault${NORMAL}" && cat "${ANSIBLE_LOG_LOCATION}"/"${PID}"-get-secrets-vault.stderr && EC=1
			fi
			rm -f "${ANSIBLE_LOG_LOCATION}"/"${PID}"-get-secrets-vault.stderr
			[[ ${EC} == 1 ]] && exit ${EC}
			[[ ${debug} == 1 ]] && set -x
			mv .tmp/$(echo "${PASSVAULT##*/}") vars/
			rm -rf .tmp
		else
			echo "Unable to clone branch "${localbranch}" of the secrets vault. Exiting!"
			exit 1
		fi
	fi
}

function remove_secrets_vault() {
	if [[ -f "${PASSVAULT}" ]]
	then
		rm -f "${PASSVAULT}"
	fi
}

function check_updates() {
	local CNTNRNAME
	CNTNRNAME="${1}"
	if [[ -f ${2} && "$(git config --file .git/config user.name)" != "" ]]
	then
		local EC
		local localbranch
		local remotebranchlist
		localbranch=$(git branch|grep '^*'|awk '{print $NF}')
		remotebranchlist=$(git branch -r)
		if [[ $(echo ${remotebranchlist}|grep '/'${localbranch}) ]]
		then
			local LOCALID
			LOCALID=$(git rev-parse --short HEAD)
			if [[ ${?} -eq 0 ]]
			then
				local REPOUSER
				local REPOPASS
				local i
				local retries
				i=0
				retries=3
				while [[ ${i} -lt ${retries} ]]
				do
					[[ $- =~ x ]] && debug=1 && [[ "${SECON}" == "true" ]] && set +x
					if [[ ${REPOUSER} == "" || ${REPOPASS} == "" ]]
					then
						REPOUSER=$(read_repo_cred "${CNTNRNAME}" "${2}" "${3}" "REPOUSER")
						REPOPASS=$(read_repo_cred "${CNTNRNAME}" "${2}" "${3}" "REPOPASS")
						[[ ${debug} == 1 ]] && set -x
					else
						break
					fi
					i=$((++i))
					[[ ${i} -eq ${retries} ]] && echo "Unable to view Repository password vault. Exiting!" && exit 1
				done
				local SET_PROXY
				local REPOPWD
				local REMOTEURL
				local REMOTEID
				[[ "$(git config --file .git/config --get remote.origin.url | grep 'github')" != "" ]] && [[ ${PROXY_ADDRESS} != "" ]] && SET_PROXY="true"
				for i in {1..3}
				do
					[[ $- =~ x ]] && debug=1 && [[ "${SECON}" == "true" ]] && set +x
					REPOPWD="${REPOPASS//@/%40}"
					[[ "$(git config --file .git/config --get remote.origin.url | grep '\/\/.*@')" == "" ]] && REMOTEURL=$(git config --file .git/config --get remote.origin.url | sed -e "s|//\(\w\)|//${REPOUSER}:${REPOPWD}@\1|") || REMOTEURL=$(git config --file .git/config --get remote.origin.url | sed -e "s|//.*@|//${REPOUSER}:${REPOPWD}@|")
					REMOTEID=$([[ ${SET_PROXY} ]] && export https_proxy=${PROXY_ADDRESS}; timeout 15 git ls-remote "${REMOTEURL}" refs/heads/"${localbranch}" 2>"${ANSIBLE_LOG_LOCATION}"/"${PID}"-remoteid.stderr | cut -c1-7)
					[[ ${debug} == 1 ]] && set -x
					[[ ${REMOTEID} == "" ]] && sleep 3 || break
				done
				if [[ "${REMOTEID}" == "" ]]
				then
					local REPO_ERR
					REPO_ERR="$(grep -i maintenance "${ANSIBLE_LOG_LOCATION}"/"${PID}"-remoteid.stderr)"
					if [[ "${REPO_ERR}" == "" ]]
					then
					 	printf "\nYour Repository credentials are invalid!\n\n" && rm -f "${2}" && rm -f "${ANSIBLE_LOG_LOCATION}"/"${PID}"-remoteid.stderr && exit 1
					else
					 	printf "\n%s\n\n" "${REPO_ERR}" && sleep 5 && rm -f "${ANSIBLE_LOG_LOCATION}"/"${PID}"-remoteid.stderr
					fi
				else
					if [[ "$(git config --file .git/config remote.origin.url | grep "\/\/.*@")" == "" ]]
					then
						git config --file .git/config remote.origin.url "$(git config --file .git/config remote.origin.url | sed -e "s|//\(\w\)|//${REPOUSER}@\1|")"
					fi
					rm -f "${ANSIBLE_LOG_LOCATION}"/"${PID}"-remoteid.stderr
				fi
				if [[ "${REMOTEID}" != "" && "${LOCALID}" != "${REMOTEID}" ]]
				then
					echo
					read -rp "Your installation package is not up to date. Updating it will overwrite any changes to tracked files. Do you want to update? ${BOLD}(y/n)${NORMAL}: " ANSWER
					echo ""
					if [[ "${ANSWER,,}" == "y" ]]
					then
						git reset -q --hard origin/"${localbranch}"
						[[ $- =~ x ]] && debug=1 && [[ "${SECON}" == "true" ]] && set +x
						git pull "$(git config --file .git/config --get remote.origin.url | sed -e "s|\(//.*\)@|\1:${REPOPASS}@|")" "${localbranch}" &>"${PWD}"/.pullerr && sed -i "s|${REPOPASS}|xxxxx|" "${PWD}"/.pullerr
						[[ ${?} == 0 ]] && echo -e "\nThe installation package has been updated. ${BOLD}Please re-run the script for the updates to take effect${NORMAL}\n\n" && EC='return 3'
						[[ ${?} != 0 ]] && echo -e "\nThe installation package update has failed with the following error:\n\n${BOLD}$(cat "${PWD}"/.pullerr)${NORMAL}\n\n" && EC='exit'
						[[ ${debug} == 1 ]] && set -x
						rm -f "${PWD}"/.pullerr
					else
						EC=':'
					fi
				fi
				${EC}
			fi
		fi
	fi
}

function get_inventory() {
	local CNTNRNAME
	CNTNRNAME="${1}"
	ANSIBLE_CMD_ARGS=$(echo "${@}" | sed "s/${CNTNRNAME} //")
	sed -i "/^vault_password_file.*$/,+d" "${ANSIBLE_CFG}"
	$(docker_cmd) exec -t ${CNTNRNAME} ansible-playbook playbooks/getinventory.yml --extra-vars "{SYS_NAME: '${SYS_DEF}'}" -e @"${SVCVAULT}" --vault-password-file Bash/get_common_vault_pass.sh -e @"${ANSIBLE_VARS}" -e "{auto_dir: '${CONTAINERWD}'}" $(remove_extra_vars_arg "$(remove_hosts_arg "${ANSIBLE_CMD_ARGS}")") -v
	GET_INVENTORY_STATUS=${?}
	[[ ${GET_INVENTORY_STATUS} != 0 ]] && exit 1
}

function get_hosts() {
	local ARG_NAME
	local MYACTION
	local HOSTS_LIST
	local CNTNRNAME
	CNTNRNAME="${1}"
	[[ "$(echo "${@}" | grep -Ew '\-\-limit')" != "" ]] && ARG_NAME="--limit" && MYACTION="get"
	[[ "$(echo "${@}" | grep -Ew '\-l')" != "" ]] && ARG_NAME="-l" && MYACTION="get"
	if [[ ${MYACTION} == "get" ]]
	then
		HOSTS_LIST=$(echo "${@}" | awk -F "${ARG_NAME} " '{print $NF}' | awk -F ' -' '{print $1}' | sed -e 's/,/ /g')
	else
		HOSTS_LIST=$($(docker_cmd) exec -i ${CNTNRNAME} ansible all -i "${INVENTORY_PATH}" --list-hosts | grep -v host | sed -e 's/^\s*\(\w.*\)$/\1/g' | sort)
	fi
	[ "$(echo "${HOSTS_LIST}" | wc -w)" -gt 1 ] && HL="${HOSTS_LIST// /,}" || HL="${HOSTS_LIST}"
}

function get_hostsinplay() {
	local hip
	local CNTNRNAME
	CNTNRNAME="${1}"
	hip=$($(docker_cmd) exec -i ${CNTNRNAME} ansible "${2}" -i "${INVENTORY_PATH}" -m debug -a msg="{{ ansible_play_hosts }}" | grep -Ev "\[|\]|\{|\}" | sort -u)
	echo ${hip}
}

function check_mode() {
	[[ "$(echo "${@}" | grep -Ew '\-\-check')" != "" ]] && echo " in check mode " || echo " "
}

function create_symlink() {
	if [[ ! -d 'Packages' ]]
	then
		if [[ -d '/data/Packages' ]]
		then
			echo "Creating symbolic link to /data/Packages"
			ln -s /data/Packages Packages
			[[ ! -d 'Packages' ]] && echo "Unable to create symbolic link to /data/Packages. Check permissions" && exit 1
		else
			echo "Unable to create symbolic link to /data/Packages as it doesn't exist"
			exit 1
		fi
	fi
}

function enable_logging() {
	LOG=true
	local CNTNRNAME
	CNTNRNAME="${1}"
	if [[ "${LOG}" == "true" ]]
	then
		LOG_FILE="${ANSIBLE_LOG_LOCATION}/play_$(basename "${0}" | awk -F '.' '{print $1}').${ENAME}.log"
		[[ "$( grep ^log_path "${ANSIBLE_CFG}" )" != "" ]] && sed -i '/^log_path = .*\$/d' "${ANSIBLE_CFG}"
		export ANSIBLE_LOG_PATH=${LOG_FILE}
		touch "${LOG_FILE}"
		[[ ${?} -ne 0 ]] && echo -e "\nUnable to create ${LOG_FILE}. Aborting run!\n" && exit 1
		chown "$(stat -c '%U' "$(pwd)")":"$(stat -c '%G' "$(pwd)")" "${LOG_FILE}"
		chmod o+rw "${LOG_FILE}"
		if [[ -z ${MYINVOKER+x} ]]
		then
			echo -e "############################################################\nAnsible Control Machine $(hostname) $(get_host_ip) ${CNTNRNAME}\nThis script was run$(check_mode "${@}")by $(whoami) on $(date)\n############################################################\n\n" > "${LOG_FILE}"
		else
			echo -e "############################################################\nAnsible Control Machine $(hostname) $(get_host_ip) ${CNTNRNAME}\nThis script was run$(check_mode "${@}")by ${MYINVOKER} on $(date)\n############################################################\n\n" > "${LOG_FILE}"
		fi
	fi
}

function run_playbook() {
	local CNTNRNAME
	CNTNRNAME="${1}"
	ANSIBLE_CMD_ARGS=$(echo "${@}" | sed "s/${CNTNRNAME} //")
	if [[ "${GET_INVENTORY_STATUS}" -eq 0 ]]
	then
		### Begin: Define the extra-vars argument list
		local EVARGS
		EVARGS="{SVCFILE: '${SVCVAULT}', $(basename "${0}" | sed -e 's/\(.*\)\.sh/\1/'): true}"
		### End
		### Begin: Determine if ASK_PASS is required
		if [[ "$(echo "${HL}" | grep -v 'vcenter')" == "" ]]
		then
			ASK_PASS=''
		else
			$(docker_cmd) exec -i ${CNTNRNAME} ansible -i "${INVENTORY_PATH}" "$(echo "${HL}" | grep -v 'vcenter')" -m debug -a 'msg={{ ansible_ssh_pass }}' --extra-vars "${EVARGS}" -e @"${SVCVAULT}" --vault-password-file Bash/get_common_vault_pass.sh &>/dev/null && [[ ${?} == 0 ]] && ASK_PASS='' || ASK_PASS='--ask-pass'
		fi
		### End
		if [[ -z ${MYINVOKER+x} ]]
		then
			$(docker_cmd) exec -t ${CNTNRNAME} ansible-playbook playbooks/site.yml -i "${INVENTORY_PATH}" --extra-vars "${EVARGS}" ${ASK_PASS} -e @"${SVCVAULT}" --vault-password-file Bash/get_common_vault_pass.sh -e @"${ANSIBLE_VARS}" -e "{auto_dir: '${CONTAINERWD}'}" ${ANSIBLE_CMD_ARGS} -v 2> "${ANSIBLE_LOG_LOCATION}"/"${PID}"-run_playbook.stderr
		else
			$(docker_cmd) exec -e MYINVOKER="${MYINVOKER}" -t ${CNTNRNAME} ansible-playbook playbooks/site.yml -i "${INVENTORY_PATH}" --extra-vars "${EVARGS}" ${ASK_PASS} -e @"${SVCVAULT}" --vault-password-file Bash/get_common_vault_pass.sh -e @"${ANSIBLE_VARS}" -e "{auto_dir: '${CONTAINERWD}'}" ${ANSIBLE_CMD_ARGS} -v 2> "${ANSIBLE_LOG_LOCATION}"/"${PID}"-run_playbook.stderr 1>/dev/null
		fi
		[[ $(grep "no vault secrets were found that could decrypt" "${ANSIBLE_LOG_LOCATION}"/"${PID}"-run_playbook.stderr | grep "${SVCVAULT}") != "" ]] && echo -e "\nUnable to decrypt ${BOLD}${SVCVAULT}${NORMAL}" && EC=1
		[[ $(grep "no vault secrets were found that could decrypt" "${ANSIBLE_LOG_LOCATION}"/"${PID}"-run_playbook.stderr) == "" ]] && [[ $(grep -i warning "${ANSIBLE_LOG_LOCATION}"/"${PID}"-run_playbook.stderr) == '' ]] && cat "${ANSIBLE_LOG_LOCATION}"/"${PID}"-run_playbook.stderr
		rm -f "${ANSIBLE_LOG_LOCATION}"/"${PID}"-run_playbook.stderr
		[[ ${EC} == 1 ]] && exit 1
	fi
}

function disable_logging() {
	if [[ "${LOG}" == "true" ]] && [[ -f "${LOG_FILE}" ]]
	then
		local FILE_TIMESTAMP
		[[ $(id -gn | wc -w) -eq 1 ]] && FILE_TIMESTAMP=$(ls --full-time --time-style=full-iso "${LOG_FILE}" | awk '{print $6"-"$7}')
		[[ $(id -gn | wc -w) -eq 2 ]] && FILE_TIMESTAMP=$(ls --full-time --time-style=full-iso "${LOG_FILE}" | awk '{print $7"-"$8}')
		unset ANSIBLE_LOG_PATH
		NEW_LOG_FILE=${LOG_FILE}.${FILE_TIMESTAMP}
		chmod 444 "${LOG_FILE}"
		mv -f "${LOG_FILE}" "${NEW_LOG_FILE}"
		echo -e "\nThe log file is ${BOLD}${PWD}/Logs/$(basename ${NEW_LOG_FILE})${NORMAL}\n\n"
	fi
}

function send_notification() {
	local CNTNRNAME
	CNTNRNAME="${1}"
	ANSIBLE_CMD_ARGS=$(echo "${@}" | sed "s/${CNTNRNAME} //")
	if [[ "$(check_mode "${ANSIBLE_CMD_ARGS}")" == " " ]]
	then
		SCRIPT_ARG="${ANSIBLE_CMD_ARGS//-/dash}"
		# Send playbook status notification
		NOTIF_ARGS=$(echo "${ANSIBLE_CMD_ARGS}" | tr ' ' '\n' | sed -e '/--tags\|-t\|--limit\|-l\|--envname/,+1d' | tr '\n' ' ')
		$(docker_cmd) exec -t ${CNTNRNAME} ansible-playbook playbooks/notify.yml --extra-vars "{SVCFILE: '${CONTAINERWD}/${SVCVAULT}', SNAME: '$(basename "${0}")', SARG: '${SCRIPT_ARG}', LFILE: '${CONTAINERWD}/${NEW_LOG_FILE}'}" --tags notify -e @"${SVCVAULT}" --vault-password-file Bash/get_common_vault_pass.sh -e @"${ANSIBLE_VARS}" ${NOTIF_ARGS} -v &>/dev/null
		SCRIPT_STATUS=${?}
	fi
}
