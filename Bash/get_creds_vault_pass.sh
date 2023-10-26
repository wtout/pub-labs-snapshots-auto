#! /bin/bash
ansible-vault view vars/.repovault.yml --vault-password-file Bash/get_repo_vault_pass.sh | awk -F "'" '{print $2}' | tail -1