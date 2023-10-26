#! /bin/bash
git config remote.origin.url | awk -F '/' '{print $NF}'
