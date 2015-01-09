#!/bin/bash

# Usage and argument parsing {{{
usage() {
	echo "usage: $0 [options]";
	echo;
	echo "OPTIONS";
	echo "  -h      Show this help message";
	echo "  -d      Dry run - echo what we want to do, but don't do it";
	echo;
}

DRY_RUN=0;
while getopts 'hd' option; do
	case "$option" in
		'h')
			usage;
			exit 1;
			;;
		'd')
			DRY_RUN=1;
			;;
		?)
			usage;
			exit 1;
			;;
	esac;
done;
# }}}

runcmd() { # {{{
	echo "+++ $@";
	if [ "$DRY_RUN" -eq 0 ]; then
		cmd="$1";
		shift;
		$cmd "$@";
	fi;
} # }}}

# Try to find config files {{{
SSHD_CONFIG_POSSIBILITIES=(
	'/etc/ssh/sshd_config'
	'/etc/sshd_config'
);
SSH_CONFIG_POSSIBILITIES=(
	'/etc/ssh/ssh_config'
	'/etc/ssh_config'
);

SSHD_CONFIG='';
SSH_CONFIG='';

for file in ${SSHD_CONFIG_POSSIBILITIES[*]}; do
	if [ -f "$file" ]; then
		echo "--- Found SSHD_CONFIG at ${file}";
		SSHD_CONFIG="${file}";
		break;
	fi;
done

for file in ${SSH_CONFIG_POSSIBILITIES[*]}; do
	if [ -f "$file" ]; then
		echo "--- Found SSH_CONFIG at ${file}";
		SSH_CONFIG="${file}";
		break;
	fi;
done;
# }}}

# Fix sshd config if we found it {{{
if [ "$SSHD_CONFIG" != '' ]; then
	SSHD_CONFIG_DIR="$(dirname "$SSHD_CONFIG")";
	lines_inserted=0;

	# Fix key exchange algorithm settings if needed
	grep '^\s*KexAlgorithms\s\+' "$SSHD_CONFIG" &>/dev/null;
	if [ "$?" -eq 0 ]; then
		runcmd sed -i 's/^\(\s*\)KexAlgorithms\s\+.*$/\1KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256/' "$SSHD_CONFIG";
	else
		lines_inserted=$((${lines_inserted} + 1));
		runcmd sed -i "${lines_inserted}i\\KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256" "$SSHD_CONFIG";
	fi;

	# If the moduli file exists, get rid of any primes less than 2000 bits
	MODULI="${SSHD_CONFIG_DIR}/moduli";
	if [ -f "$MODULI" ]; then
		# Ugly hack for portable in-place awk
		runcmd awk '$5 > 2000' "$MODULI" > >(cat <(sleep 1) - > "$MODULI");
	else
		runcmd touch "$MODULI";
	fi;

	# If there's nothing left in the moduli file (or it didn't exist at all), we should populate it
	if [ "$(stat --printf=%s "$MODULI")" -lt 10 ]; then
		runcmd rm "$MODULI";
		runcmd ssh-keygen -T "$MODULI" -f <(ssh-keygen -q -G /dev/stdout -b 4096 2> >(while read line; do echo ">>> ${line}" > /dev/stderr; done));
	fi;

	# Force v2 protocol
	grep '^\s*Protocol\s\+' "$SSHD_CONFIG" &>/dev/null;
	if [ "$?" -eq 0 ]; then
		runcmd sed -i 's/^\(\s*\)Protocol\s\+.*$/\1Protocol 2/' "$SSHD_CONFIG";
	else
		lines_inserted=$((${lines_inserted} + 1));
		runcmd sed -i "${lines_inserted}iProtocol 2" "$SSHD_CONFIG";
	fi;

	# Get rid of DSA and ECDSA keys; create RSA and Ed25519 if they don't exist
	runcmd sed -i 's/^\s*HostKey/d' "$SSHD_CONFIG";
	lines_inserted=$((${lines_inserted} + 1));
	runcmd sed -i "${lines_inserted}iHostKey ${SSHD_CONFIG_DIR}/ssh_host_ed25519_key" "$SSHD_CONFIG";
	lines_inserted=$((${lines_inserted} + 1));
	runcmd sed -i "${lines_inserted}iHostKey ${SSHD_CONFIG_DIR}/ssh_host_rsa_key" "$SSHD_CONFIG";
	runcmd rm -f "${SSHD_CONFIG_DIR}/ssh_host_key{,.pub}";
	runcmd rm -f "${SSHD_CONFIG_DIR}/ssh_host_dsa_key{,.pub}";
	runcmd rm -f "${SSHD_CONFIG_DIR}/ssh_host_ecdsa_key{,.pub}";
	if [ ! -f "${SSHD_CONFIG_DIR}/ssh_host_ed25519_key" ] || [ ! -f "${SSHD_CONFIG_DIR}/ssh_host_ed25519_key.pub" ]; then
		runcmd ssh-keygen -t ed25519 -f /etc/ssh_host_ed25519_key < /dev/null;
	fi;
	if [ ! -f "${SSHD_CONFIG_DIR}/ssh_host_rsa_key" ] || [ ! -f "${SSHD_CONFIG_DIR}/ssh_host_rsa_key.pub" ]; then
		runcmd ssh-keygen -t rsa -b 4096 -f /etc/ssh_host_rsa_key < /dev/null;
	fi;

	# Limit symmetric ciphers to good modern ones
	grep '^\s*Ciphers\s\+' "$SSHD_CONFIG" &>/dev/null;
	if [ "$?" -eq 0 ]; then
		runcmd sed -i 's/^\(\s*\)Ciphers\s\+.*$/\1Ciphers chacha20-poly1305@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr/' "$SSHD_CONFIG";
	else
		lines_inserted=$((${lines_inserted} + 1));
		runcmd sed -i "${lines_inserted}iCiphers chacha20-poly1305@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" "$SSHD_CONFIG";
	fi;

	# Limit MAC algos to good modern ones with long keys, ETM only
	grep '^\s*MACs\s\+' "$SSHD_CONFIG" &>/dev/null;
	if [ "$?" -eq 0 ]; then
		runcmd sed -i 's/^\(\s*\)MACs\s\+.*$/\1MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-ripemd160-etm@openssh.com,umac-128-etm@openssh.com' "$SSHD_CONFIG";
	else
		lines_inserted=$((${lines_inserted} + 1));
		runcmd sed -i "${lines_inserted}iMACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-ripemd160-etm@openssh.com,umac-128-etm@openssh.com" "$SSHD_CONFIG";
	fi;
fi;
# }}}

