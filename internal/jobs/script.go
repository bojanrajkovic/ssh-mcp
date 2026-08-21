package jobs

import (
	"fmt"
	"strconv"
	"strings"
)

// The remote side of a job is four small shell scripts. They are written for
// POSIX sh rather than bash, because a remote is as likely to be busybox as it
// is to be a GNU userland.

// rootLoop opens a loop over the candidate job roots, binding r to each.
func rootLoop() string {
	return "for r in " + strings.Join(roots, " ") + "; do\n"
}

// launchScript starts a job detached from the connection that started it.
//
// Two shell details keep it detached. Only the setsid command is backgrounded,
// with `echo started` after it: backgrounding the whole list would leave a
// subshell holding the SSH channel's stdout and stderr, and bash then waits
// on it, so ssh never returns. The command runs inside a subshell so the
// redirections cover all of it and an `exit` inside it cannot skip writing
// the exit code.
func launchScript(jobID ID, command string) string {
	inner := "(\n" + command + "\n) >\"$d/out\" 2>\"$d/err\"\necho $? >\"$d/rc\""

	var b strings.Builder
	b.WriteString("d=''\n")
	b.WriteString(rootLoop())
	fmt.Fprintf(&b, "  if mkdir -p \"$r/%s\" 2>/dev/null; then d=\"$r/%s\"; break; fi\n", jobID, jobID)
	b.WriteString("done\n")
	b.WriteString("[ -n \"$d\" ] || { echo 'no writable job root on this host' >&2; exit 1; }\n")
	fmt.Fprintf(&b, "printf '%%s' %s > \"$d/cmd\"\n", shellQuote(command))
	fmt.Fprintf(&b, "s=%s\n", shellQuote(inner))
	// The child shell needs the job directory, and it is a separate process.
	b.WriteString("export d\n")
	// setsid is absent on macOS remotes; nohup alone still detaches enough
	// for ssh to return, it just leaves the job in the same session.
	b.WriteString("if command -v setsid >/dev/null 2>&1; then\n")
	b.WriteString("  setsid nohup sh -c \"$s\" </dev/null >/dev/null 2>&1 &\n")
	b.WriteString("else\n")
	b.WriteString("  nohup sh -c \"$s\" </dev/null >/dev/null 2>&1 &\n")
	b.WriteString("fi\n")
	b.WriteString("echo started\n")
	return b.String()
}

// statusScript reports one job as key=value lines.
func statusScript(jobID ID) string {
	var b strings.Builder
	b.WriteString(rootLoop())
	fmt.Fprintf(&b, "  d=\"$r/%s\"\n", jobID)
	b.WriteString("  if [ -d \"$d\" ]; then\n")
	b.WriteString("    if [ -f \"$d/rc\" ]; then\n")
	b.WriteString("      echo \"state=finished\"\n")
	b.WriteString("      echo \"rc=$(cat \"$d/rc\")\"\n")
	b.WriteString("    else\n")
	b.WriteString("      echo \"state=running\"\n")
	b.WriteString("    fi\n")
	// Newlines are stripped so one command stays one key=value line. A
	// multi-line command reads back joined rather than breaking the parse.
	b.WriteString("    [ -f \"$d/cmd\" ] && echo \"cmd=$(tr -d '\\n' < \"$d/cmd\")\"\n")
	b.WriteString("    exit 0\n")
	b.WriteString("  fi\n")
	b.WriteString("done\n")
	b.WriteString("echo \"state=missing\"\n")
	return b.String()
}

// readScript emits one of a job's stream files, or nothing when it is absent.
func readScript(jobID ID, name string) string {
	var b strings.Builder
	b.WriteString(rootLoop())
	fmt.Fprintf(&b, "  if [ -f \"$r/%s/%s\" ]; then exec cat \"$r/%s/%s\"; fi\n", jobID, name, jobID, name)
	b.WriteString("done\n")
	return b.String()
}

// sweepScript removes job directories older than days and prints what went.
func sweepScript(days int) string {
	var b strings.Builder
	b.WriteString(rootLoop())
	b.WriteString("  [ -d \"$r\" ] || continue\n")
	fmt.Fprintf(&b,
		"  find \"$r\" -mindepth 1 -maxdepth 1 -type d -mtime +%s -print -exec rm -rf {} + 2>/dev/null\n",
		strconv.Itoa(days))
	b.WriteString("done\n")
	return b.String()
}
