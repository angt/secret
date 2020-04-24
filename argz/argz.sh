_argz() {
	local last opts
	last="${COMP_WORDS[COMP_CWORD]}"
	COMP_WORDS[COMP_CWORD]="help"
	opts="$("${COMP_WORDS[@]}" 2>/dev/null | awk '{print $1}' )"
	case "$opts" in
		'') ;;
		CMD) mapfile -t COMPREPLY < <(compgen -A command -- "$last") ;;
		DIR) mapfile -t COMPREPLY < <(compgen -A dir -- "$last") ;;
		FILE) mapfile -t COMPREPLY < <(compgen -A file -- "$last") ;;
		*) mapfile -t COMPREPLY < <(compgen -W "$opts" -- "$last") ;;
	esac
}
