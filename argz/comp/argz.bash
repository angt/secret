_argz_reply() {
	while IFS='' read -r line; do COMPREPLY+=("$line"); done
}

_argz() {
	local last opts
	last="${COMP_WORDS[COMP_CWORD]}"
	COMP_WORDS[COMP_CWORD]="help"
	opts="$("${COMP_WORDS[@]}" 2>/dev/null | awk '{print $1}' )"
	case "$opts" in
		'') ;;
		CMD)  _argz_reply < <(compgen -A command -- "$last") ;;
		DIR)  _argz_reply < <(compgen -A dir     -- "$last") ;;
		FILE) _argz_reply < <(compgen -A file    -- "$last") ;;
		*)    _argz_reply < <(compgen -W "$opts" -- "$last") ;;
	esac
}
