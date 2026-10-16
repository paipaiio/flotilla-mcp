import { describe, expect, it } from "vitest";
import { classifyCommand } from "../src/index.js";

describe("read-only allowlist looks at arguments, not just the binary", () => {
  it.each([
    "ip netns exec x touch /tmp/x",
    "ip -batch /tmp/cmds",
    "rg --pre /tmp/evil x /etc",
    "find / -fprintf /tmp/x %p",
    "find / -fls /tmp/x",
    "git diff --output=/etc/x",
    "git log --ext-diff",
    "ss -K dst 1.2.3.4",
    "hostname evil",
    "hostname -F /tmp/n",
    "date -s 2020-01-01",
    "date --set=2020-01-01",
    "date 010100002020",
    "journalctl --vacuum-time=1s",
    "journalctl --rotate",
    "dmesg -C",
    "dmesg --read-clear",
    "ping -f 1.2.3.4",
    "sysctl -w net.ipv4.ip_forward=0",
    "sysctl net.ipv4.ip_forward=0",
    "sysctl -p",
    "sysctl --system",
    "tc qdisc add dev eth0 root fq",
    "sort -o /etc/passwd x",
    "uniq in.txt /etc/out",
    "top",
  ])("%s is not read-only", (command) => {
    expect(classifyCommand(command)).not.toBe("read-only");
  });

  it.each([
    "ip netns exec x rm -rf /",
    "timeout 5 rm -rf /",
    "nice -n 10 rm -rf /",
  ])("%s is still forbidden behind a wrapper", (command) => {
    expect(classifyCommand(command)).toBe("forbidden");
  });

  it.each([
    "sysctl net.ipv4.tcp_congestion_control",
    "sysctl -n net.core.default_qdisc",
    "sysctl -a",
    "tc qdisc show dev eth0",
    "tc -s qdisc show",
    "cd /etc && ls -la",
    "docker compose ps",
    "docker compose logs --tail 50 app",
    "docker network ls",
    "docker volume inspect data",
    "pm2 list",
    "pm2 jlist",
    "systemctl list-timers",
    "ps aux | sort -k4 -nr | head",
    "cut -d: -f1 /etc/passwd | sort | uniq -c",
    "top -b -n 1",
    "date +%F",
    "hostname -I",
    "ip -br addr",
    "dmesg -T",
    "journalctl -u nginx -n 50 --no-pager",
  ])("%s is read-only", (command) => {
    expect(classifyCommand(command)).toBe("read-only");
  });
});

describe("abbreviated and bundled options (getopt_long accepts unambiguous prefixes)", () => {
  it.each([
    "sort --out=/tmp/x /etc/hosts",
    "sort --o /tmp/x /etc/hosts",
    "sort -S1 --compress-p=sh /etc/hosts",
    "sort -uo /tmp/x /etc/hosts",
    "dmesg -Tc",
    "dmesg --clea",
    "hostname --file=/tmp/x",
    "hostname --fil /tmp/x",
    "journalctl --rot",
    "journalctl --vacuum-ti=1s",
    "sysctl --sys",
    "sysctl -aw kernel.x=1",
    "ss -tK",
    "ss --ki",
    "git diff --out=/tmp/x",
    "git log --ext-d",
    "git branch -D old",
    "git branch --delete old",
    "git branch newbranch",
    "git tag v9",
    "git tag -d v1",
    "git remote add evil https://x",
    "git remote set-url origin https://x",
    "date -us 2020-01-01",
    "date 010100002020",
  ])("%s is not read-only", (cmd) => {
    expect(classifyCommand(cmd)).not.toBe("read-only");
  });

  it.each([
    "date -Iseconds",
    "date -d yesterday +%F",
    "date -r /etc/hosts",
    "date +%s",
    "date -u",
    "dmesg -T",
    "dmesg --color=always",
    "hostname -I",
    "hostname --fqdn",
    "journalctl --since today -u nginx",
    "journalctl --unit=nginx --reverse",
    "sysctl -a",
    "sysctl net.ipv4.tcp_congestion_control",
    "sort -k2 -t, file",
    "sort -rn file",
    "ss -tlnp",
    "git branch",
    "git branch -a",
    "git branch -vv",
    "git tag",
    "git tag -l 'v1*'",
    "git remote -v",
    "git remote show origin",
    "git remote get-url origin",
    "git diff --stat",
    "git log --exit-code",
  ])("%s stays read-only", (cmd) => {
    expect(classifyCommand(cmd)).toBe("read-only");
  });
});
