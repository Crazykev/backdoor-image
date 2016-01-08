#!/bin/bash

VERBOSITY=0
TEMP_D=""
DEFAULT_USER="backdoor"

error() { echo "$@" 1>&2; }

Usage() {
	cat <<EOF
Usage: ${0##*/} [ options ] target

   add a 'backdoor' user to a image or filesystem at 'target'

   options:
      --import-id U      use 'ssh-import-id' to get ssh public keys
                         may be used more than once.
      --force            required to operate on / filesystem
      --password P       set password P, implies --password-auth
      --password-auth    enable password auth
      --pubkeys  F       add public keys from file 'F'
                         default: ~/.ssh/id_rsa.pub unless --password
                         or --import-id specified
      --user      U      use user 'U' (default: '${DEFAULT_USER}')
EOF
}

bad_Usage() { Usage 1>&2; [ $# -eq 0 ] || error "$@"; exit 1; }
cleanup() {
	[ -z "${TEMP_D}" -o ! -d "${TEMP_D}" ] || rm -Rf "${TEMP_D}"
}

debug() {
	local level=${1}; shift;
	[ "${level}" -gt "${VERBOSITY}" ] && return
	error "${@}"
}

mod_sshd_bool() {
	local cfg="$1" kn="$2" target="$3" dry=${4:-false}
	local ws=$' \t' msg=""
	local match="^\([#]\{0,1\}\)[#$ws]*$kn\([$ws]\+\)\(yes\|no\)"
	local cur="" hsh="#"
	cur=$(sed -n "s/$match/\1\3/p" "$cfg") ||
		{ error "failed to read $cfg"; return 1; }
	if [ -n "$cur" ]; then
		case "$cur" in
			"#$target") msg="uncommenting, '$target' line";;
			"#*") msg="uncommenting, changing '${cur#$hsh}' to '$target'";;
			"$target") msg="nochange";;
			"*") msg="changing '$cur' to '$target'";;
		esac
		if [ "$msg" = "nochange" ]; then
			debug 1 "no change to $cfg necessary"
		else
			debug 1 "updating $cfg: $msg"
			$dry && return
			sed -i "s/$match/$kn\2${target}/" "$cfg" ||
				{ error "failed to update $cfg"; return 1; }
		fi
	else
		debug 1 "appending entry for '$kn $target' to $cfg"
		$dry && return
		echo "$kn $target" >> "$cfg" ||
			{ error "failed to append entry to $cfg"; return 1; }
	fi
	return 0
}

test_mod_sshd_cfg() {
	local kn="PasswordAuthentication"
	echo "#$kn   yes" > f1
	echo "#$kn  no" > f2
	echo "$kn yes" > f3
	echo "$kn no" > f4
	: > f5
	for f in f1 f2 f3 f4 f5; do
		mod_sshd_bool "$f" PasswordAuthentication yes true
	done
}

add_group_ent() {
	local group="$1" gid="$2" fgroup="$3" dry="${4:-false}"
	local grent="$group:x:$gid:"
	if grep -q "^$group:" "$fgroup"; then
		debug 1 "remove $group from group file"
		$dry || sed -i "/^$group:/d" "$fgroup" ||
			{ error "failed to remove user from group"; return 1; }
	fi

	debug 1 "append entry to group: $grent"
	if ! $dry; then
		echo "$grent" >> "$fgroup" ||
			{ error "failed to update group file"; return 1; }
	fi
	return 0
}

add_passwd_ent() {
	local user="$1" uid="$2" gid="$3" home="$4" fpasswd="$5" dry=${6:-false}

	if grep -q "^$user:" "$fpasswd"; then
		debug 1 "remove $user from password file"
		$dry || sed -i "/^$user:/d" "$fpasswd" ||
			{ error "failed to remove user from password file"; return 1; }
	fi

	local pwent="$user:x:$uid:$gid:backdoor:$home:/bin/bash"
	debug 1 "append entry to passwd: $pwent"
	if ! $dry; then
		echo "$pwent" >> "$fpasswd" ||
			{ error "failed to update passwd file"; return 1; }
	fi
}

encrypt_pass() {
	local pass="$1" fmt="${2-\$6\$}"
	enc=$(echo "$pass" |
		perl -e '
			$p=<STDIN>; chomp($p);
			$salt = join "", map { (q(a)..q(z))[rand(26)] } 1 .. 8;
			if (${ARGV[0]}) { $salt = "${ARGV[0]}$salt\$"; }
			print crypt($p, "$salt") . "\n";' "$fmt") || return
	[ -n "${enc}" ] && [ -z "${fmt}" -o "${enc#${fmt}}" != "${fmt}" ] &&
	_RET="$enc"
}

add_shadow_ent() {
	local user="$1" pass="$2" fshadow="$3" dry="$4"
	local encrypt_pre="\$6\$" shent="" encpass="" pwchange=""

	# if input was '$6$' format, just use it verbatum
	if [ "${pass#${encrypt_pre}}" != "${pass}" ]; then
		debug 1 "using encrypted password from cmdline"
		encpass="$pass"
	else
		encrypt_pass "$pass" && encpass="$_RET" ||
			{ error "failed to encrypt password"; return 1; }
	fi

	# pwchange is number of days since 1970
	pwchange=$(($(date +"(%Y-1970)*365 + 10#%j")))
	shent="$user:$encpass:$pwchange:0:99999:7:::"

	if grep -q "^$user:" "$fshadow"; then
		debug 1 "remove $user from shadow file"
		$dry || sed -i "/^$user:/d" "$fshadow" ||
			{ error "failed to remove user from shadow"; return 1; }
	fi

	debug 1 "append entry to shadow: $shent"
	if ! $dry; then
		echo "$shent" >> "$fshadow" ||
			{ error "failed to update shadow file"; return 1; }
	fi
	return 0

}

add_sudo_ent() {
	local user="$1" mp="$2" dry="$3"

	local target="/etc/sudoers.d/99-$user"

	local ent="$user ALL=(ALL) NOPASSWD:ALL"
	local start="#BACKDOOR_START_${user}"
	local end="#BACKDOOR_end_${user}"
	local content=$(printf "%s\n%s\n%s\n" "$start" "$ent" "$end")

	if [ -f "$mp/etc/lsb-release" ] &&
		grep -i lucid -q "$mp/etc/lsb-release"; then
		target="/etc/sudoers"
		debug 2 "$mp does not seem to support sudoers.d"
		debug 1 "add sudoers ($mp,$target): $ent"
		if grep -q "^$start$" "$mp/$target"; then
			debug 2 "removing $user entry from $target"
			if ! $dry; then
				sed -i "/^${start}$/,/^${end}$/d" "$target" ||
					{ error "failed update $target"; return 1; }
			fi
		fi
		if ! $dry; then
			( umask 226 && echo "$content" >> "$mp/$target" ) ||
				{ error "failed to add sudoers entry to $target"; return 1; }
		fi
	else
		debug 1 "add sudoers ($mp,$target): $ent"
		if ! $dry; then
			rm -f "$mp/$target" &&
				( umask 226 && echo "$content" > "$mp/$target" ) ||
				{ error "failed to add sudoers entry to $target"; return 1; }
		fi
	fi
}

add_user() {
	local user="$1" pass="$2" uid="$3" gid="$4" home="$5"
	local rootd="$6" dry="${7:-false}"
	local fpasswd="$rootd/etc/passwd" fshadow="$rootd/etc/shadow"
	local fgroup="$rootd/etc/group"

	[ -f "$fpasswd" ] || { error "no password file"; return 1; }
	[ -f "$fshadow" ] || { error "no shadow file"; return 1; }
	[ -f "$fgroup" ] || { error "no group file"; return 1; }

	local group="$user" f="" t=""
	
	add_passwd_ent "$user" "$uid" "$gid" "$home" "$fpasswd" "$dry" || return 1
	add_group_ent "$group" "$gid" "$fgroup" "$dry" || return 1
	add_shadow_ent "$user" "$pass" "$fshadow" "$dry" || return 1

	debug 1 "create $rootd/home/$user"
	if ! $dry; then
		mkdir -p "$rootd/home/$user" &&
			chown $uid:$gid "$rootd/home/$user" ||
			{ error "failed to make home dir"; return 1; }
		for f in "$rootd/etc/skel/".* "$rootd/etc/skel/"*; do
			[ -e "$f" ] || continue
			t="$rootd/home/$user/${f##*/}"
			[ ! -e "$t" ] || continue
			cp -a "$f" "$t" && chown -R "$uid:$gid" "$t" ||
				{ error "failed to copy $f to $t"; return 1; }
		done
	fi
}

add_user_keys() {
	local keys="$1" dir="$2" ownership="$3" dry="${4:-false}"
	debug 1 "add ssh keys to $dir with $ownership"
	$dry && return
	mkdir -p "$dir" &&
		cp "$keys" "$dir/authorized_keys" &&
		chmod 600 "$dir/authorized_keys" &&
		chown "$ownership" "$dir" "$dir/authorized_keys" &&
		chmod 700 "$dir" ||
		{ error "failed to add user keys"; return 1; }
	if [ $VERBOSITY -ge 1 ]; then
		debug 1 "added ssh keys:"
		sed "s,^,| ," "$keys"
	fi
}

gen_ssh_keys() {
	local mp="$1" types="${2:-rsa}" dry="${3:-false}"
	local ktype="" file="" ftmpl="/etc/ssh/ssh_host_%s_key" out=""
	for ktype in $types; do
		file=${ftmpl//%s/$ktype}
		if [ -f "$mp/$file" ]; then
			debug 2 "existing key for $mp/$file"
			continue
		fi
		debug 1 "ssh-keygen -t $ktype -N '' -f '$file' -C backdoor"
		$dry && continue
		out=$(ssh-keygen -t "$ktype" -N '' -f "$mp/$file" -C backdoor 2>&1) || {
			error "$out"
			error "failed generate keytype $ktype";
			return 1;
		}
		out=$(ssh-keygen -l -f "$mp/$file")
		debug 1 "$out"
	done
}

apply_changes() {
	local mp="$1" user="$2" password="$3" pwauth="$4" pubkeys="$5"
	local dry="${6:-false}"
	local home="/home/$user" key=""
 	local uid="9999" gid="9999"

	local sshcfg="$mp/etc/ssh/sshd_config"
	[ -f "$sshcfg" ] || 
		{ error "$sshcfg did no exist"; return 1; }

	key="PubkeyAuthentication"
	mod_sshd_bool "$sshcfg" "$key" "yes" "$dry" ||
		{ error "failed to set $key to yes"; return 1; }

	if $pwauth; then
		key="PasswordAuthentication"
		mod_sshd_bool "$sshcfg" "$key" "yes" "$dry" ||
			{ error "failed to set $key to yes"; return 1; }
	fi

	gen_ssh_keys "$mp" "rsa" "$dry" || return 1

	add_user "$user" "$password" "$uid" "$gid" "$home" "$mp" "$dry" || return 1

	[ -z "$pubkeys" ] ||
		add_user_keys "$pubkeys" "$mp/$home/.ssh" "$uid:$gid" || return 1

	add_sudo_ent "$user" "$mp" "$dry" || return 1

}

main() {
	short_opts="hv"
	long_opts="help,dry-run,force,import-id:,password:,password-auth,pubkeys:,user:,verbose"
	getopt_out=$(getopt --name "${0##*/}" \
		--options "${short_opts}" --long "${long_opts}" -- "$@") &&
		eval set -- "${getopt_out}" ||
		bad_Usage

	local user="" password="" pwauth=false pubkeys="" import_ids="" dry=false
	local target="" pkfile="" force=false
	user="${DEFAULT_USER}"

	local args=""
	args=( "$@" )
	unset args[${#args[@]}-1]

	while [ $# -ne 0 ]; do
		cur=${1}; next=${2};
		case "$cur" in
			-h|--help) Usage ; exit 0;;
			   --dry-run) dry=true;;
			   --force) force=true;;
			   --import-id)
					import_ids="${import_ids:+${import_ids} }$next";
					shift;;
			   --password) password=$next; shift;;
			   --password-auth) pwauth=true;;
			   --pubkeys) pubkeys=$next; shift;;
			   --user) user=$next; shift;;
			-v|--verbose) VERBOSITY=$((${VERBOSITY}+1));;
			--) shift; break;;
		esac
		shift;
	done

	[ $# -ne 0 ] || { bad_Usage "must provide image"; return 1; }
	[ $# -ge 2 ] && { bad_Usage "too many arguments: $*"; return 1; }

	[ "$(id -u)" = "0" ] || 
		{ error "sorry, must be root"; return 1; }

	target="$1"
	if [ -d "$target" ]; then
		if [ "$target" -ef "/" ] && ! $force; then
			error "you must specify --force to operate on /"
			return 1
		fi
	elif [ -f "$target" ]; then
		local vopt="" mcu="mount-callback-umount"
		if [ ${VERBOSITY} -ge 2 ]; then
			vopt="-v"
		fi
		if ! command -v "$mcu" >/dev/null 2>&1; then
			if [ -x "${0%/*}/$mcu" ]; then
				PATH="${0%/*}:$PATH"
			elif command -v "mount-image-callback" >/dev/null 2>&1; then
				mcu="mount-image-callback"
			else
				error "No '$mcu' or 'mount-image-callback' in PATH"
				return 1
			fi
		fi
		exec "$mcu" $vopt -- "$target" "$0" "${args[@]}" _MOUNTPOINT_
	else
		[ -f "$target" ] || { error "$target: not a file"; return 1; }
	fi

	if [ -n "$password" ] && ! which perl >/dev/null 2>&1; then
		{ error "perl required for making password"; return 1; }
		pwauth=true
	fi

	{ [ -z "$import_ids" ] || which ssh-import-id >/dev/null 2>&1; } ||
		{ error "you do not have ssh-import-id"; return 1; }

	TEMP_D=$(mktemp -d "${TMPDIR:-/tmp}/${0##*/}.XXXXXX") ||
		{ error "failed to make tempdir"; return 1; }
	trap cleanup EXIT

	pkfile="${TEMP_D}/pubkeys"
	if [ -z "$password" -a -z "$pubkeys" -a -z "$import_ids" ]; then
		[ -f ~/.ssh/id_rsa.pub ] || {
			error "must specify one of --password, --pubkeys, --import-id"
			error "either pass an argument or create ~/.ssh/id_rsa.pub"
			return 1
		}
		debug 1 "set pubkeys to ~/.ssh/id_rsa.pub"
		pubkeys=$(echo ~/.ssh/id_rsa.pub)
	fi

	if [ -n "$pubkeys" ]; then
		cp "$pubkeys" "$pkfile" ||
			{ error "failed to copy $pubkeys"; return 1; }
	fi

	if [ -n "$import_ids" ]; then
		ssh-import-id --output "$pkfile.i" ${import_ids} &&
			cat "$pkfile.i" >> "$pkfile" ||
			{ error "failed to import ssh users: $import_ids"; return 1; }
	fi

	[ -f "$pkfile" ] || pkfile=""

	apply_changes "$target" "$user" "$password" "$pwauth" "$pkfile"
	[ $? -eq 0 ] || { error "failed to apply changes"; return 1; }

	error "added user '$user' to $target"
	[ -n "$password" ] && error "set password to $password."
	$pwauth && error "enabled password auth" ||
		error "did not enable password auth"
	[ -n "$pubkeys" ] && error "added pubkeys from $pubkeys."
	[ -n "$import_ids" ] && error "imported ssh keys for $import_ids"
	return 0
}

main "$@"

# vi: ts=4 noexpandtab
