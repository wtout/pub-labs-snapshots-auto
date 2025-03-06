#! /bin/bash
password=$(git config --file .git/config remote.origin.url | awk -F '/' '{print $NF}' | sed -e "s|^pub-||")
[[ "${password}" != *".git" ]] && password="${password}.git"
echo ${password}
