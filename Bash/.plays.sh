source $(dirname "${0}")/functions_library.sh

# Main
[[ $- =~ x ]] && BASHOPTION='-x '
ORIG_ARGS="${@}"
ENV_LIST=$(get_envname_list "${ORIG_ARGS}")
NEW_ARGS=$(clean_arguments '--envname' "${ENV_LIST}" "${ORIG_ARGS}" | xargs)
IFS=' ' read -r -a LOOP_LIST <<< "${ENV_LIST}"
ENV_LIST_LENGTH=$(echo "${ENV_LIST}" | wc -w)
SCRIPT_NAME=$(echo "${0}" | sed 's|play_||')

[[ "${ENV_LIST_LENGTH}" -gt 1 ]] && echo
for i in "${!LOOP_LIST[@]}"
do
	[[ "${i}" -gt 0 ]] && sleep "${i}"
	if [[ "${ENV_LIST_LENGTH}" -gt 1 ]]
	then
		[[ ${BASHOPTION} =~ x ]] && NOHUP_DEST="${LOOP_LIST[i]}.out" || NOHUP_DEST="/dev/null"
		nohup bash ${BASHOPTION}${SCRIPT_NAME} --envname "${LOOP_LIST[i]}" "${NEW_ARGS}" &>"${NOHUP_DEST}" &
		echo "Executing: bash ${BASHOPTION}${SCRIPT_NAME} --envname "${LOOP_LIST[i]}" "${NEW_ARGS}" &>"${NOHUP_DEST}" &"
	else
		bash ${BASHOPTION}${SCRIPT_NAME} --envname "${LOOP_LIST[i]}" "${NEW_ARGS}" &
	fi
done
trap "kill -2 ${!}" INT
[[ "${ENV_LIST_LENGTH}" -gt 1 ]] && echo "Please wait..."
wait