# Functions declaration

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
	AUTHFILE=${HOME}/.docker/config.json
	MYDOMAIN=$(echo ${CONTAINERREPO}|cut -d '/' -f1)
	MYRELEASE=$(get_os)
	case ${MYRELEASE} in
		CentOS*)
			MYJSONFILE=${AUTHFILE}
			;;
		AlmaLinux*)
			MYJSONFILE=${XDG_RUNTIME_DIR}/containers/auth.json
			;;
		*)
			;;
	esac
	if [[ ${MYJSONFILE} == ${AUTHFILE} ]]
	then
		if [[ ! -f ${MYJSONFILE} || "$(grep ${MYDOMAIN} ${MYJSONFILE})" == "" ]]
		then
			LOGGEDIN=false
		fi
	else
		if [[ ! -f ${AUTHFILE} || "$(grep ${MYDOMAIN} ${AUTHFILE})" == "" ]] && [[ ! -f ${MYJSONFILE} || "$(grep ${MYDOMAIN} ${MYJSONFILE})" == "" ]]
		then
			LOGGEDIN=false
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
		AlmaLinux*)
			echo "docker"
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
	[[ "${IIDLIST}" != "" ]] && $(docker_cmd) rmi ${IIDLIST}
}

function check_image() {
	$(docker_cmd) images | grep -E "${CONTAINERREPO}.*${ANSIBLE_VERSION}" &>/dev/null
	return ${?}
}

function check_container() {
	$(docker_cmd) ps -a | grep -w ${CONTAINERNAME} &>/dev/null
	return ${?}
}

function start_container() {
	if [[ $(check_container; echo "${?}") -ne 0 ]]
	then
		[[ ! -d ${HOME}/.ssh ]] && mkdir ${HOME}/.ssh
		echo "Starting container ${CONTAINERNAME}"
		[[ $- =~ x ]] && debug=1 && [[ "${SECON}" == "true" ]] && set +x
		if [[ "${ANSIBLE_LOG_PATH}" == "" ]]
		then
			$(docker_cmd) run --rm -e MYPROXY=${PROXY_ADDRESS} -e MYHOME=${HOME} -e MYHOSTNAME=$(hostname) -e MYCONTAINERNAME=${CONTAINERNAME} -e MYIP=$(get_host_ip) --user ansible -w ${CONTAINERWD} -v /data:/data:z -v /tmp:/tmp:z -v ${PWD}:${CONTAINERWD}:z --name ${CONTAINERNAME} -it -d --entrypoint /bin/bash ${CONTAINERREPO}:${ANSIBLE_VERSION}
		else
			$(docker_cmd) run --rm -e ANSIBLE_LOG_PATH=${ANSIBLE_LOG_PATH} -e ANSIBLE_FORKS=${NUM_HOSTSINPLAY} -e MYPROXY=${PROXY_ADDRESS} -e MYHOME=${HOME} -e MYHOSTNAME=$(hostname) -e MYCONTAINERNAME=${CONTAINERNAME} -e MYIP=$(get_host_ip) -e MYHOSTOS=$(get_os) --user ansible -w ${CONTAINERWD} -v /data:/data:z -v /tmp:/tmp:z -v ${HOME}/.ssh:/home/ansible/.ssh:z -v ${PWD}:${CONTAINERWD}:z --name ${CONTAINERNAME} -it -d --entrypoint /bin/bash ${CONTAINERREPO}:${ANSIBLE_VERSION}
		fi
		[[ ${debug} == 1 ]] && set -x
		[[ $(check_container; echo "${?}") -ne 0 ]] && echo "Unable to start container ${CONTAINERNAME}" && exit 1
	fi
}

function stop_container() {
	if [[ $(check_container; echo "${?}") -eq 0 ]]
	then
		echo "Stopping container ${CONTAINERNAME}"
		$(docker_cmd) stop ${CONTAINERNAME} &>/dev/null
	fi
}

function check_repeat_job() {
	ps -ef | grep -w "${ENAME}" | grep "Bash/play_" | grep -vwE "${PID}|grep" | grep -vw 'cd'
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
		if ! git config remote.origin.url &>/dev/null
		then
			echo "You are not authorized to use this automation. Aborting!"
			exit 1
		fi
		if [[ "$(git config user.name)" == "" ]]
		then
			IFS=' ' read -rp "Enter your full name [ENTER]: " NAME SURNAME
			if [[ "$(git config remote.origin.url | grep "\/\/.*@")" == "" ]]
			then
				git config user.name "${NAME} ${SURNAME}" || EC=1
			else
				[[ "${SURNAME}" != "" ]] && [[ "$(git config remote.origin.url | sed -e 's/.*\/\/\(.*\)@.*/\1/')" == *"$(echo ${SURNAME:0:5} | tr '[:upper:]' '[:lower:]')"* ]] && git config user.name "${NAME} ${SURNAME}" || EC=1
			fi
		fi
		[[ ${EC} -eq 1 ]] && echo "Invalid full name. Aborting!" && exit ${EC}
		if [[ "$(git config user.email)" == "" ]]
		then
			NAME=$(git config user.name | awk '{print $1}' | tr '[:upper:]' '[:lower:]')
			SURNAME=$(git config user.name | awk '{print $NF}' | tr '[:upper:]' '[:lower:]')
			read -rp "Enter your email address [ENTER]: " GIT_EMAIL_ADDRESS
			if [[ "$(git config remote.origin.url | grep "\/\/.*@")" == "" ]] && [[ "${GIT_EMAIL_ADDRESS}" != "" ]] && [[ "$(echo "${GIT_EMAIL_ADDRESS}" | cut -d '@' -f1)" == *"$(echo ${NAME:0:2} | tr '[:upper:]' '[:lower:]')"* ]] && [[ "$(echo "${GIT_EMAIL_ADDRESS}" | cut -d '@' -f1)" == *"$(echo ${SURNAME:0:5} | tr '[:upper:]' '[:lower:]')"* ]]
			then
				git config user.email "${GIT_EMAIL_ADDRESS}" && git config remote.origin.url "$(git config remote.origin.url | sed -e "s|//\(\w\)|//$(echo "${GIT_EMAIL_ADDRESS}" | cut -d '@' -f1)@\1|")" || EC=1
			else
				[[ "$(git config remote.origin.url)" == *"$(echo "${GIT_EMAIL_ADDRESS}" | cut -d '@' -f1)"* ]] && git config user.email "${GIT_EMAIL_ADDRESS}" || EC=1
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
	MYPROXY=$(grep -r "^proxy.*=.*" /etc/environment /etc/profile /etc/profile.d/ ~/.bashrc ~/.bash_profile | cut -d '"' -f2 | uniq)
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
			select_creds primary vcenter_service pass "${PCREDS_LIST[@]}" 1>/dev/null && read -r PPPASS <<< "$(select_creds primary vcenter_service pass "${PCREDS_LIST[@]}" "${PCREDS_LIST[@]}")"
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

function get_creds_prefix() {
    local FILETOCHECK
    local DATACENTER
    local CREDS_PREFIX
	[[ -f "${SYS_DEF}" ]] && FILETOCHECK="${SYS_DEF}" || FILETOCHECK="${SYS_ALL}"
	DATACENTER=$(cat "${FILETOCHECK}" | sed "/^$/d" | grep -A32 -P "^datacenter:$" | sed -n "/${1}:/,+2p" | sed -n "/name:/,1p" | awk -F ': ' '{print $NF}' | sed "s/'//g")
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
	if [[ $(get_creds_prefix ${1}) ]]
	then
		view_vault vars/passwords.yml Bash/get_common_vault_pass.sh | grep ^$(get_creds_prefix ${1}) | sed "s/'//g"
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
	[[ -f ${1} ]] && [[ -f ${2} ]] && [[ -x ${2} ]] && $(docker_cmd) exec -it ${CONTAINERNAME} ansible-vault encrypt "${1}" --vault-password-file "${2}" &>"${ANSIBLE_LOG_LOCATION}"/encrypt_error."${PID}"
	if [[ -s "${ANSIBLE_LOG_LOCATION}/encrypt_error.${PID}" && "$(grep 'successful' "${ANSIBLE_LOG_LOCATION}/encrypt_error.${PID}")" == "" ]]
	then
		cat "${ANSIBLE_LOG_LOCATION}"/encrypt_error."${PID}"
		exit 1
	else
		rm "${ANSIBLE_LOG_LOCATION}"/encrypt_error."${PID}"
	fi
}

function view_vault() {
	[[ -f ${1} ]] && [[ -f ${2} ]] && [[ -x ${2} ]] && $(docker_cmd) exec -i ${CONTAINERNAME} ansible-vault view "${1}" --vault-password-file "${2}" 2>"${ANSIBLE_LOG_LOCATION}"/decrypt_error."${PID}"
	[[ $(grep "was not found" "${ANSIBLE_LOG_LOCATION}"/decrypt_error."${PID}") != "" ]] && sed -i "/^vault_password_file.*$/,+d" "${ANSIBLE_CFG}" && $(docker_cmd) exec -i ${CONTAINERNAME} ansible-vault view "${1}" --vault-password-file "${2}" &>/dev/null
	rm -f "${ANSIBLE_LOG_LOCATION}"/decrypt_error."${PID}"
}

function get_repo_creds() {
	local REPOUSER
	local REPOPASS
	if [[ -f ${1} ]]
	then
		grep 'REPOPASS=' "${1}" 1>/dev/null && rm -f "${1}"
	else
		echo -e "\n\nYour ${BOLD}$(git config --get remote.origin.url|cut -d '/' -f3|cut -d '@' -f2)${NORMAL} Repository credentials are needed"
		read -rp "Enter your Repository username [ENTER]: " REPOUSER
		read -rsp "Enter your Repository token [ENTER]: " REPOPASS
		echo
		if [[ ${REPOUSER} != "" && ${REPOPASS} != "" ]]
		then
			[[ $- =~ x ]] && debug=1 && [[ "${SECON}" == "true" ]] && set +x
			printf "REPOUSER='%s'\nREPOPASS='%s'\n" "${REPOUSER}" "${REPOPASS}" > "${1}"
			add_write_permission "${1}"
			encrypt_vault "${1}" "${2}"
			[[ ${debug} == 1 ]] && set -x
			sudo chown "$(stat -c '%U' "$(pwd)")":"$(stat -c '%G' "$(pwd)")" "${1}"
			sudo chmod 644 "${1}"
		else
			echo
			echo "Unable to get repo credentials"
			echo
			[[ -z ${MYINVOKER+x} ]] && stop_container && exit 1
		fi
	fi
}

function check_updates() {
	if [[ -f ${1} && "$(git config user.name)" != "" ]]
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
						[[ ${debug} == 1 ]] && set -x
						read -r REPOUSER <<< "$(view_vault "${1}" "${2}" | grep USER | cut -d "'" -f2)"
						read -r REPOPASS <<< "$(view_vault "${1}" "${2}" | grep PASS | cut -d "'" -f2)"
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
				[[ "$(git config --get remote.origin.url | grep 'wwwin-github')" != "" ]] && [[ ${PROXY_ADDRESS} != "" ]] && SET_PROXY="true"
				for i in {1..3}
				do
					[[ $- =~ x ]] && debug=1 && [[ "${SECON}" == "true" ]] && set +x
					REPOPWD="${REPOPASS//@/%40}"
					[[ "$(git config --get remote.origin.url | grep '\/\/.*@')" == "" ]] && REMOTEURL=$(git config --get remote.origin.url | sed -e "s|//\(\w\)|//${REPOUSER}:${REPOPWD}@\1|") || REMOTEURL=$(git config --get remote.origin.url | sed -e "s|//.*@|//${REPOUSER}:${REPOPWD}@|")
					REMOTEID=$([[ ${SET_PROXY} ]] && export https_proxy=${PROXY_ADDRESS}; git ls-remote "${REMOTEURL}" refs/heads/"${localbranch}" 2>"${ANSIBLE_LOG_LOCATION}"/"${PID}"-remoteid.stderr | cut -c1-7)
					[[ ${debug} == 1 ]] && set -x
					[[ ${REMOTEID} == "" ]] && sleep 3 || break
				done
				if [[ "${REMOTEID}" == "" ]]
				then
					local REPO_ERR
					REPO_ERR="$(grep -i maintenance "${ANSIBLE_LOG_LOCATION}"/"${PID}"-remoteid.stderr)"
					if [[ "${REPO_ERR}" == "" ]]
					then
					 	printf "\nYour Repository credentials are invalid!\n\n" && rm -f "${1}" && rm -f "${ANSIBLE_LOG_LOCATION}"/"${PID}"-remoteid.stderr && exit 1
					else
					 	printf "\n%s" "${REPO_ERR}" && rm -f "${ANSIBLE_LOG_LOCATION}"/"${PID}"-remoteid.stderr && exit 1
					fi
				else
					if [[ "$(git config remote.origin.url | grep "\/\/.*@")" == "" ]]
					then
						git config remote.origin.url "$(git config remote.origin.url | sed -e "s|//\(\w\)|//${REPOUSER}@\1|")"
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
						git pull "$(git config --get remote.origin.url | sed -e "s|\(//.*\)@|\1:${REPOPASS}@|")" "${localbranch}" &>"${PWD}"/.pullerr && sed -i "s|${REPOPASS}|xxxxx|" "${PWD}"/.pullerr
                        [[ ${?} == 0 ]] && echo -e "\nThe installation package has been updated. ${BOLD}Please re-run the script for the updates to take effect${NORMAL}\n\n" && EC='return 3'
                        [[ ${?} != 0 ]] && echo -e "\nThe installation package update has failed with the following error:\n\n${BOLD}$(cat "${PWD}"/.pullerr)${NORMAL}\n\n" && EC='exit'
                        rm -f "${PWD}"/.pullerr
					else
						EC='continue'
					fi
				fi
				${EC}
			fi
		fi
	fi
}

function get_inventory() {
	sed -i "/^vault_password_file.*$/,+d" "${ANSIBLE_CFG}"
	$(docker_cmd) exec -it ${CONTAINERNAME} ansible-playbook playbooks/getinventory.yml --extra-vars "{SYS_NAME: '${SYS_DEF}'}" -e @"${SVCVAULT}" --vault-password-file Bash/get_common_vault_pass.sh -e @"${ANSIBLE_VARS}" -e "{auto_dir: '${CONTAINERWD}'}" $(remove_extra_vars_arg "$(remove_hosts_arg "${@}")") -v
	GET_INVENTORY_STATUS=${?}
	[[ ${GET_INVENTORY_STATUS} != 0 ]] && exit 1
}

function get_hosts() {
	local ARG_NAME
	local MYACTION
	local HOSTS_LIST
	[[ "$(echo "${@}" | grep -Ew '\-\-limit')" != "" ]] && ARG_NAME="--limit" && MYACTION="get"
	[[ "$(echo "${@}" | grep -Ew '\-l')" != "" ]] && ARG_NAME="-l" && MYACTION="get"
	if [[ ${MYACTION} == "get" ]]
	then
		HOSTS_LIST=$(echo "${@}" | awk -F "${ARG_NAME} " '{print $NF}' | awk -F ' -' '{print $1}' | sed -e 's/,/ /g')
	else
		HOSTS_LIST=$($(docker_cmd) exec -i ${CONTAINERNAME} ansible all -i "${INVENTORY_PATH}" --list-hosts | grep -v host | sed -e 's/^\s*\(\w.*\)$/\1/g' | sort)
	fi
	[ "$(echo "${HOSTS_LIST}" | wc -w)" -gt 1 ] && HL="${HOSTS_LIST// /,}" || HL="${HOSTS_LIST}"
}

function get_hostsinplay() {
	local hip
	hip=$($(docker_cmd) exec -i ${CONTAINERNAME} ansible "${1}" -i "${INVENTORY_PATH}" -m debug -a msg="{{ ansible_play_hosts }}" | grep -Ev "\[|\]|\{|\}" | sort -u)
	echo ${hip}
}
function get_hostsinplay() {
	local hip
	hip=$(ansible "${1}" -i "${INVENTORY_PATH}" -m debug -a msg="{{ ansible_play_hosts }}" | grep -Ev "\[|\]|\{|\}" | sort -u)
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
	if [[ "${LOG}" == "true" ]]
	then
		LOG_FILE="${ANSIBLE_LOG_LOCATION}/$(basename "${0}" | awk -F '.' '{print $1}').${ENAME}.log"
		[[ "$( grep ^log_path "${ANSIBLE_CFG}" )" != "" ]] && sed -i '/^log_path = .*\$/d' "${ANSIBLE_CFG}"
		export ANSIBLE_LOG_PATH=${LOG_FILE}
		touch "${LOG_FILE}"
		[[ ${?} -ne 0 ]] && echo -e "\nUnable to create ${LOG_FILE}. Aborting run!\n" && exit 1
		chown "$(stat -c '%U' "$(pwd)")":"$(stat -c '%G' "$(pwd)")" "${LOG_FILE}"
		chmod o+rw "${LOG_FILE}"
		if [[ -z ${MYINVOKER+x} ]]
		then
			echo -e "############################################################\nAnsible Control Machine $(hostname) $(get_host_ip) ${CONTAINERNAME}\nThis script was run$(check_mode "${@}")by $(whoami) on $(date)\n############################################################\n\n" > "${LOG_FILE}"
		else
			echo -e "############################################################\nAnsible Control Machine $(hostname) $(get_host_ip) ${CONTAINERNAME}\nThis script was run$(check_mode "${@}")by ${MYINVOKER} on $(date)\n############################################################\n\n" > "${LOG_FILE}"
		fi
	fi
}

function run_playbook() {
	if [[ ${GET_INVENTORY_STATUS} == 0 || -f ${CRVAULT} ]]
	then
		### Begin: Determine if ASK_PASS is required
		$(docker_cmd) exec -it ${CONTAINERNAME} ansible "${HL}" -m debug -a 'msg={{ ansible_ssh_pass }}' &>/dev/null && [[ ${?} == 0 ]] && ASK_PASS=''
		### End
		### Begin: Define the extra-vars argument list
		local EVARGS
		EVARGS="{SVCFILE: '${SVCVAULT}', $(echo "${0}" | sed -e 's/.*play_\(.*\)\.sh/\1/'): true}"
		if [[ -z ${MYINVOKER+x} ]]
		then
			$(docker_cmd) exec -it ${CONTAINERNAME} ansible-playbook playbooks/site.yml -i "${INVENTORY_PATH}" --extra-vars "${EVARGS}" ${ASK_PASS} -e @"${PASSVAULT}" -e @"${SVCVAULT}" --vault-password-file Bash/get_common_vault_pass.sh -e @"${ANSIBLE_VARS}" -e "{auto_dir: '${CONTAINERWD}'}" ${@} -v 2> "${ANSIBLE_LOG_LOCATION}"/"${PID}".stderr
		else
			$(docker_cmd) exec -it ${CONTAINERNAME} ansible-playbook playbooks/site.yml -i "${INVENTORY_PATH}" --extra-vars "${EVARGS}" ${ASK_PASS} -e @"${PASSVAULT}" -e @"${SVCVAULT}" --vault-password-file Bash/get_common_vault_pass.sh -e @"${ANSIBLE_VARS}" -e "{auto_dir: '${CONTAINERWD}'}" ${@} -v 2> "${ANSIBLE_LOG_LOCATION}"/"${PID}".stderr 1>/dev/null
		fi
		[[ $(grep "no vault secrets were found that could decrypt" "${ANSIBLE_LOG_LOCATION}"/"${PID}".stderr | grep  "${PASSVAULT}") != "" ]] && echo -e "\nUnable to decrypt ${BOLD}${PASSVAULT}${NORMAL}" && EC=1
		[[ $(grep "no vault secrets were found that could decrypt" "${ANSIBLE_LOG_LOCATION}"/"${PID}".stderr | grep "${CRVAULT}") != "" ]] && echo -e "\nUnable to decrypt ${BOLD}${CRVAULT}${NORMAL}" && rm -f "${CRVAULT}" && EC=1
		[[ $(grep "no vault secrets were found that could decrypt" "${ANSIBLE_LOG_LOCATION}"/"${PID}".stderr) == "" ]] && [[ $(grep -i warning "${ANSIBLE_LOG_LOCATION}"/"${PID}".stderr) == '' ]] && cat "${ANSIBLE_LOG_LOCATION}"/"${PID}".stderr
		rm -f "${ANSIBLE_LOG_LOCATION}"/"${PID}".stderr
		[[ ${EC} == 1 ]] && exit 1
	fi
}

function disable_logging() {
	if [[ "${LOG}" == "true" ]] && [[ -f "${LOG_FILE}" ]]
	then
		unset ANSIBLE_LOG_PATH
		NEW_LOG_FILE=${LOG_FILE}.$(ls --full-time "${LOG_FILE}" | awk '{print $6"-"$7}')
		chmod 444 "${LOG_FILE}"
		mv -f "${LOG_FILE}" "${NEW_LOG_FILE}"
		echo -e "\nThe log file is ${BOLD}${PWD}/Logs/$(basename ${NEW_LOG_FILE})${NORMAL}\n\n"
	fi
}

function send_notification() {
	if [[ "$(check_mode "${@}")" == " " ]]
	then
		SCRIPT_ARG="${@//-/dash}"
		# Send playbook status notification
		$(docker_cmd) exec -it ${CONTAINERNAME} ansible-playbook playbooks/notify.yml --extra-vars "{SVCFILE: '${CONTAINERWD}/${SVCVAULT}', SNAME: '$(basename "${0}")', SARG: '${SCRIPT_ARG}', LFILE: '${CONTAINERWD}/${NEW_LOG_FILE}', NHOSTS: '${NUM_HOSTSINPLAY}'}" --tags notify -e @"${PASSVAULT}" -e @"${SVCVAULT}" --vault-password-file Bash/get_common_vault_pass.sh -e @"${ANSIBLE_VARS}" -e "{AUTOHOME: '${PWD}'}" -v &>/dev/null
		SCRIPT_STATUS=${?}
	fi
}

# Parameters definition
ANSIBLE_CFG="ansible.cfg"
ANSIBLE_LOG_LOCATION="Logs"
BOLD=$(tput bold)
NORMAL=$(tput sgr0)
ANSIBLE_VERSION='7.7.0'
ANSIBLE_VARS="vars/datacenters.yml"
PASSVAULT="vars/passwords.yml"
REPOVAULT="vars/.repovault.yml"
CONTAINERWD="/home/ansible/$(basename ${PWD})"
CONTAINERREPO="containers.cisco.com/watout/ansible"
USER_ACCTS="svc r labsadmin appadmin infrabuild"

# Main
PID="${$}"
add_user_uid_gid
add_user_docker_group
create_dir "${ANSIBLE_LOG_LOCATION}"
check_arguments "${@}"
check_docker_login
restart_docker
NEW_ARGS=$(check_hosts_limit "${@}")
set -- && set -- "${@}" "${NEW_ARGS}"
ORIG_ARGS="${@}"
ENAME=$(get_envname "${ORIG_ARGS}")
check_repeat_job && echo -e "\nRunning multiple instances of ${BOLD}$(basename "${0}")${NORMAL} is prohibited. Aborting!\n\n" && exit 1
INVENTORY_PATH="inventories/${ENAME}"
CRVAULT="${INVENTORY_PATH}/group_vars/vault.yml"
SYS_DEF="Definitions/${ENAME}.yml"
SYS_ALL="${INVENTORY_PATH}/group_vars/all.yml"
SVCVAULT="vars/.svc_acct_creds_${ENAME}.yml"
CONTAINERNAME="$(whoami | cut -d '@' -f1)_ansible_${ANSIBLE_VERSION}_${ENAME}"
NEW_ARGS=$(clean_arguments '--envname' "${ENAME}" "${@}")
check_deffile
set -- && set -- "${@}" "${NEW_ARGS}"
git_config
SECON=$([[ "$(git config user.email|cut -d '@' -f1)" == "watout" ]] && echo "false" || echo "true")
check_container && stop_container
image_prune
start_container
[[ $- =~ x ]] && debug=1 && [[ "${SECON}" == "true" ]] && set +x
PCREDS_LIST=$(get_creds primary)
PROXY_ADDRESS=$(get_proxy) || PA=${?}
[[ ${PA} -eq 1 ]] && echo -e "\n${PROXY_ADDRESS}\n" && exit ${PA}
[[ ${debug} == 1 ]] && set -x
add_write_permission ${PWD}/vars
if [[ -z ${MYINVOKER+x} ]]
then
	get_repo_creds "${REPOVAULT}" Bash/get_repo_vault_pass.sh
	check_updates "${REPOVAULT}" Bash/get_repo_vault_pass.sh
	CHECK_UPDATE_STATUS=${?}
else
	CHECK_UPDATE_STATUS=0
fi
if [[ ${CHECK_UPDATE_STATUS} -eq 3 ]]
then
    stop_container
    return 1
else
	[[ $- =~ x ]] && debug=1 && [[ "${SECON}" == "true" ]] && set +x
	rm -f "${SVCVAULT}"; umask 0022; touch "${SVCVAULT}"
	for c in ${USER_ACCTS}
	do
		select_creds primary ${c} user "${PCREDS_LIST[@]}" 1>/dev/null && echo -e "P${c^^}_USER: '$(select_creds primary ${c} user "${PCREDS_LIST[@]}")'" >> "${SVCVAULT}"
		select_creds primary ${c} pass "${PCREDS_LIST[@]}" 1>/dev/null && echo -e "P${c^^}_PASS: '$(select_creds primary ${c} pass "${PCREDS_LIST[@]}")'" >> "${SVCVAULT}"
	done
	[[ ${debug} == 1 ]] && set -x
	add_write_permission "${SVCVAULT}"
	encrypt_vault "${SVCVAULT}" Bash/get_common_vault_pass.sh
	sudo chown "$(stat -c '%U' "$(pwd)")":"$(stat -c '%G' "$(pwd)")" "${SVCVAULT}"
	sudo chmod 644 "${SVCVAULT}"
	get_inventory "${@}"
	get_hosts "${@}"
	NUM_HOSTSINPLAY=$([[ "$(get_hostsinplay "${HL}" | wc -w)" != "0" ]] && get_hostsinplay "${HL}" | wc -w || echo "1")
	stop_container
	add_write_permission "${PWD}/roles"
	add_write_permission "${PWD}/roles/*"
	add_write_permission "${PWD}/roles/*/files"
	enable_logging "${@}"
	start_container
	run_playbook "${@}"
	stop_container
	disable_logging
	sleep 10
	start_container &>/dev/null
	send_notification "${ORIG_ARGS}"
	stop_container &>/dev/null
	return ${SCRIPT_STATUS}
fi
