/**
 * --create-user: replace a root/admin login with a dedicated low-privilege
 * account, so users never have to set one up by hand.
 */
import { OnboardError, assertPublicKeyLine, shellQuote } from "./onboard.js";

const USERNAME_RE = /^[a-z_][a-z0-9_-]{0,31}$/;
const RESERVED_USERS = new Set(["root", "daemon", "bin", "sys", "nobody", "sshd"]);

/**
 * sudo rules for a created user: exactly the systemctl commands Flotilla's
 * service tools run (no `edit` → editor-as-root, no daemon-reload, no unit
 * file writes). Journal reads need no sudo at all: the user joins the
 * systemd-journal group.
 *
 * sudo ≥ 1.9.10 gets regex rules that pin the arguments to "<verb> <unit>"
 * (unit may not start with "-", so no options can be smuggled in). Older sudo
 * only has globs, whose "*" also matches extra arguments — the fallback.
 */
const UNIT = "[A-Za-z0-9@._\\:][A-Za-z0-9@._\\:-]*";
const REGEX_RULES = (bin: string) =>
  `${bin} ^(start|stop|restart|reload) ${UNIT}\\$, ${bin} ^status ${UNIT} --no-pager -l\\$`;
const GLOB_RULES = (bin: string) =>
  ["status *", "start *", "stop *", "restart *", "reload *"].map((a) => `${bin} ${a}`).join(", ");

/**
 * One idempotent POSIX-sh command: create the user, install the fleet public
 * key for it, add journal read access, optionally drop a visudo-validated
 * sudoers allowlist. Works with useradd (Debian/RHEL) and busybox adduser
 * (Alpine). Must run as root — the caller wraps it in sudo when the
 * first-contact account is not uid 0.
 */
export function buildCreateUserCommand(user: string, publicKey: string, withSudo: boolean): string {
  return `sh -c ${shellQuote(buildCreateUserScript(user, publicKey, withSudo))}`;
}

/** The POSIX-sh script behind buildCreateUserCommand (exposed for syntax checks). */
export function buildCreateUserScript(user: string, publicKey: string, withSudo: boolean): string {
  if (!USERNAME_RE.test(user) || RESERVED_USERS.has(user)) {
    throw new OnboardError(`Invalid user name for --create-user: "${user}"`, "invalid", { user });
  }
  const key = shellQuote(assertPublicKeyLine(publicKey));
  const lines = [
    "set -e",
    `U=${user}`,
    "CREATED=0",
    'if ! id "$U" >/dev/null 2>&1; then',
    '  if command -v useradd >/dev/null 2>&1; then useradd -m -s /bin/sh "$U";',
    '  elif command -v adduser >/dev/null 2>&1; then adduser -D -s /bin/sh "$U";',
    '  else echo "no useradd/adduser on this system" >&2; exit 3; fi',
    "  CREATED=1",
    "fi",
    // A fresh account has a locked ("!") password; sshd without PAM refuses
    // key logins for locked accounts. "*" = no password, but not locked.
    'if [ "$CREATED" = 1 ]; then usermod -p "*" "$U" 2>/dev/null || echo "$U:*" | chpasswd -e 2>/dev/null || true; fi',
    `H=$(awk -F: -v u="$U" '$1==u{print $6}' /etc/passwd)`,
    '[ -n "$H" ] || { echo "cannot find home of $U" >&2; exit 4; }',
    'mkdir -p "$H/.ssh" && chmod 700 "$H/.ssh"',
    'touch "$H/.ssh/authorized_keys" && chmod 600 "$H/.ssh/authorized_keys"',
    `grep -qxF ${key} "$H/.ssh/authorized_keys" || echo ${key} >> "$H/.ssh/authorized_keys"`,
    'chown -R "$U": "$H/.ssh"',
    // Read-only journal access without sudo (service-logs).
    'for g in systemd-journal adm; do if grep -q "^$g:" /etc/group; then (usermod -aG "$g" "$U" || addgroup "$U" "$g") >/dev/null 2>&1 || true; fi; done',
  ];
  if (withSudo) {
    lines.push(
      'if P=$(command -v systemctl 2>/dev/null) && [ -d /etc/sudoers.d ]; then',
      // "Sudo version 1.9.15p5" → regex rules from 1.9.10 on.
      "  SV=$(sudo -V 2>/dev/null | sed -n 's/^Sudo version \\([0-9]*\\)\\.\\([0-9]*\\)\\.\\([0-9]*\\).*/\\1 \\2 \\3/p' | head -n 1)",
      "  RE=0",
      '  if [ -n "$SV" ]; then set -- $SV; if [ "$1" -gt 1 ] || { [ "$1" -eq 1 ] && { [ "$2" -gt 9 ] || { [ "$2" -eq 9 ] && [ "$3" -ge 10 ]; }; }; }; then RE=1; fi; fi',
      `  if [ "$RE" = 1 ]; then R="${REGEX_RULES("$P")}"; else R="${GLOB_RULES("$P")}"; fi`,
      "  T=$(mktemp)",
      '  printf "%s ALL=(root) NOPASSWD: %s\\n" "$U" "$R" > "$T"',
      '  if command -v visudo >/dev/null 2>&1; then visudo -cf "$T" >/dev/null || { rm -f "$T"; echo "sudoers validation failed" >&2; exit 5; }; fi',
      '  cp "$T" "/etc/sudoers.d/flotilla-$U" && chmod 440 "/etc/sudoers.d/flotilla-$U"; rm -f "$T"',
      "fi",
    );
  }
  lines.push("echo FLOTILLA_USER_READY");
  return lines.join("\n");
}
