#! /bin/bash
git config --file .git/config remote.origin.url | awk -F '/' '{print $NF}' | sed -e "s|^pub-||"
