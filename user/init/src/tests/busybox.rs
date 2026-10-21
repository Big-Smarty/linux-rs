// SPDX-License-Identifier: GPL-2.0-only
//! `busybox` group (`-- bbrun`): real, unmodified Linux userland on the kernel. A deterministic list
//! of BusyBox v1.36.1 commands (the host's static `/usr/bin/busybox`, installed by the harness as
//! `/bin/busybox` in a second initramfs module, never committed) runs one by one, each in a forked
//! child with stdout and stderr on one pipe; the line per command names it, how it ended (exit
//! status or terminating signal) and its escaped output. The same list runs on the pinned Linux
//! 6.18.57 (`xtask/oracle/expected.tsv` holds that output) and on this kernel, so every system
//! call BusyBox, its libc and the shell make is compared through what the programs do with the
//! answers, not through a trace.
//!
//! Commands are chosen to print the same on both kernels: no clock value, no pid, no inode number,
//! no `/proc` (the procfs lane covers those applets), no network, no randomness. The data files
//! are those of `xtask::fixture` (`/bb`, mtime 2001-09-09 01:46:40 UTC), the children get an
//! explicit environment and a null stdin, and an armed `SIGALRM` ends a child that hangs.

use core::fmt::Write as _;

use syscalls::{Errno, Sysno};

use super::proc::{spawn, wait4};
use super::{addr, addr_mut, die, emit, sys};

const BUSYBOX: &[u8] = b"/bin/busybox\0";
/// The environment of every command: `PATH` for `sh`, `HOME` as the kernel gives init.
const ENVP: [&str; 3] = ["PATH=/bin", "HOME=/", "LC_ALL=C"];
/// Raw output kept per command; the rest is counted and dropped (read, so the child never blocks).
const KEEP: usize = 700;
/// The most raw output any group keeps per command (`Exec::keep` chooses below it).
pub(super) const KEEP_MAX: usize = 2048;
/// A child that outlives this many seconds dies of `SIGALRM`.
const GUARD_SECONDS: usize = 20;
const O_RDWR: usize = 2;

/// One command: the label of its line and `argv` (`argv[0]` is the applet or `busybox`).
struct Cmd {
    label: &'static str,
    argv: &'static [&'static str],
}

macro_rules! cmds {
    ($(($label:literal, [$($arg:literal),+ $(,)?])),+ $(,)?) => {
        &[$(Cmd { label: $label, argv: &[$($arg),+] }),+]
    };
}

/// The command list. A label is unique and stable: the `expected.tsv` row is keyed by it.
const COMMANDS: &[Cmd] = cmds![
    // Utilities with a fixed output.
    ("echo", ["echo", "hello", "world"]),
    ("echo-n", ["echo", "-n", "no newline"]),
    ("echo-e", ["echo", "-e", "a\\tb\\\\c\\x41"]),
    (
        "printf",
        [
            "printf",
            "%s-%d-%x-%o|%5.2f|%-4s|\\n",
            "abc",
            "42",
            "255",
            "8",
            "3.14159",
            "ab"
        ]
    ),
    ("seq", ["seq", "1", "5"]),
    ("seq-step", ["seq", "10", "-3", "0"]),
    ("expr", ["expr", "2", "+", "3", "*", "4"]),
    ("expr-match", ["expr", "hello", ":", "h\\(.*\\)o"]),
    ("expr-zero-division", ["expr", "1", "/", "0"]),
    ("basename", ["basename", "/a/b/c.txt", ".txt"]),
    ("dirname", ["dirname", "/a/b/c.txt"]),
    ("true", ["true"]),
    ("false", ["false"]),
    ("test-file", ["test", "-f", "/bb/hello.txt"]),
    ("test-dir-missing", ["test", "-d", "/bb/nothing"]),
    ("bracket", ["[", "5", "-gt", "3", "]"]),
    ("whoami", ["whoami"]),
    ("id", ["id"]),
    ("id-u", ["id", "-u"]),
    ("uname", ["uname", "-s", "-m", "-n", "-o"]),
    ("pwd", ["pwd"]),
    ("env", ["env"]),
    ("printenv", ["printenv", "HOME", "PATH"]),
    ("tty", ["tty"]),
    ("sleep-0", ["sleep", "0"]),
    ("yes-head", ["sh", "-c", "yes | head -n 3"]),
    // Reading files.
    ("cat", ["cat", "/bb/hello.txt", "/bb/csv.txt"]),
    ("cat-missing", ["cat", "/bb/nothing"]),
    ("cat-dir", ["cat", "/bb"]),
    ("cat-noperm", ["cat", "/bb/noperm"]),
    ("wc", ["wc", "/bb/words.txt", "/bb/lines.txt"]),
    ("wc-l", ["wc", "-l", "/bb/lines.txt"]),
    ("head", ["head", "-n", "2", "/bb/lines.txt"]),
    ("head-c", ["head", "-c", "7", "/bb/words.txt"]),
    ("tail", ["tail", "-n", "2", "/bb/lines.txt"]),
    ("tail-c", ["tail", "-c", "6", "/bb/words.txt"]),
    ("sort", ["sort", "/bb/lines.txt"]),
    ("sort-n", ["sort", "-n", "/bb/nums.txt"]),
    ("sort-rn", ["sort", "-rn", "/bb/nums.txt"]),
    ("sort-u", ["sort", "-u", "/bb/lines.txt"]),
    ("uniq-c", ["sh", "-c", "sort /bb/lines.txt | uniq -c"]),
    ("tac", ["tac", "/bb/nums.txt"]),
    ("rev", ["rev", "/bb/words.txt"]),
    ("nl", ["nl", "/bb/csv.txt"]),
    ("cut", ["cut", "-d,", "-f2,3", "/bb/csv.txt"]),
    ("cut-c", ["cut", "-c", "1-3", "/bb/words.txt"]),
    ("paste", ["paste", "/bb/nums.txt", "/bb/nums.txt"]),
    ("tr", ["sh", "-c", "echo Hello | tr a-z A-Z"]),
    ("tr-d", ["sh", "-c", "echo hello | tr -d l"]),
    ("fold", ["fold", "-w", "10", "/bb/words.txt"]),
    ("expand", ["sh", "-c", "printf 'a\\tb\\n' | expand"]),
    ("sed-s", ["sed", "s/apple/PEAR/", "/bb/lines.txt"]),
    ("sed-n", ["sed", "-n", "2,3p", "/bb/lines.txt"]),
    ("sed-d", ["sed", "/an/d", "/bb/lines.txt"]),
    ("sed-g", ["sed", "s/a/A/g", "/bb/words.txt"]),
    ("grep", ["grep", "apple", "/bb/lines.txt"]),
    ("grep-c", ["grep", "-c", "an", "/bb/lines.txt"]),
    ("grep-v", ["grep", "-v", "an", "/bb/lines.txt"]),
    ("grep-n", ["grep", "-n", "ch", "/bb/lines.txt"]),
    ("grep-r", ["grep", "-r", "dd", "/bb/tree"]),
    ("grep-none", ["grep", "zzz", "/bb/lines.txt"]),
    ("awk-field", ["awk", "{print $2}", "/bb/words.txt"]),
    (
        "awk-sum",
        ["awk", "-F,", "NR>1{s+=$2} END{print s}", "/bb/csv.txt"]
    ),
    (
        "awk-printf",
        ["awk", "BEGIN{printf \"%d %s %.1f\\n\", 7, \"x\", 2.5}"]
    ),
    (
        "od",
        ["od", "-A", "x", "-t", "x1", "-N", "48", "/bb/bin.dat"]
    ),
    ("od-c", ["od", "-c", "/bb/hello.txt"]),
    ("hexdump", ["hexdump", "-C", "/bb/hello.txt"]),
    ("xxd", ["xxd", "-l", "32", "/bb/bin.dat"]),
    ("md5sum", ["md5sum", "/bb/bin.dat", "/bb/hello.txt"]),
    ("sha1sum", ["sha1sum", "/bb/bin.dat"]),
    ("sha256sum", ["sha256sum", "/bb/bin.dat", "/bb/hello.txt"]),
    ("cksum", ["cksum", "/bb/bin.dat"]),
    ("base64", ["base64", "/bb/hello.txt"]),
    (
        "base64-d",
        ["sh", "-c", "base64 /bb/bin.dat | base64 -d | md5sum"]
    ),
    ("cmp", ["cmp", "/bb/hello.txt", "/bb/words.txt"]),
    ("cmp-same", ["cmp", "/bb/hello.txt", "/bb/hello.txt"]),
    ("diff", ["diff", "/bb/nums.txt", "/bb/lines.txt"]),
    ("comm", ["comm", "/bb/lines.txt", "/bb/lines.txt"]),
    (
        "dd",
        [
            "sh",
            "-c",
            "dd if=/bb/bin.dat bs=16 skip=2 count=1 2>/dev/null | od -A n -t x1"
        ]
    ),
    // The file system.
    ("ls", ["ls", "/bb/tree"]),
    ("ls-a", ["ls", "-a", "/bb/tree"]),
    ("ls-l", ["ls", "-l", "/bb"]),
    (
        "ls-ld",
        ["ls", "-ld", "/bb", "/bb/hello.txt", "/bb/tree/link"]
    ),
    ("ls-R", ["ls", "-R", "/bb/tree"]),
    ("ls-missing", ["ls", "/bb/nothing"]),
    (
        "stat",
        [
            "stat",
            "-c",
            "%a %s %F %h %u %g %n",
            "/bb/hello.txt",
            "/bb",
            "/bb/tree/link",
            "/dev/null"
        ]
    ),
    ("stat-L", ["stat", "-L", "-c", "%F %s %N", "/bb/tree/link"]),
    ("stat-missing", ["stat", "/bb/nothing"]),
    ("find", ["sh", "-c", "find /bb/tree | sort"]),
    (
        "find-name",
        ["sh", "-c", "find /bb/tree -name '*.txt' | sort"]
    ),
    ("find-type", ["sh", "-c", "find /bb/tree -type d | sort"]),
    (
        "find-exec",
        ["sh", "-c", "find /bb/tree -name d.txt -exec cat {} \\;"]
    ),
    ("readlink", ["readlink", "/bb/tree/link"]),
    ("readlink-f", ["readlink", "-f", "/bb/tree/link"]),
    ("realpath", ["realpath", "/bb/tree/a/../e.txt"]),
    ("du", ["du", "-a", "/bb/tree/a"]),
    (
        "mkdir",
        [
            "sh",
            "-c",
            "mkdir /tmp/d1 && mkdir -p /tmp/d1/a/b && ls -R /tmp/d1"
        ]
    ),
    ("mkdir-exists", ["mkdir", "/bb"]),
    ("mkdir-missing-parent", ["mkdir", "/tmp/x/y"]),
    (
        "rmdir",
        ["sh", "-c", "mkdir /tmp/r && rmdir /tmp/r && ls /tmp/r"]
    ),
    (
        "rmdir-notempty",
        ["sh", "-c", "mkdir -p /tmp/rn/x && rmdir /tmp/rn"]
    ),
    (
        "touch",
        ["sh", "-c", "touch /tmp/t1 && stat -c '%s %F' /tmp/t1"]
    ),
    (
        "touch-d",
        [
            "sh",
            "-c",
            "touch -d @86400 /tmp/t2 && ls -l --full-time /tmp/t2 | cut -d' ' -f6-"
        ]
    ),
    (
        "rm",
        ["sh", "-c", "touch /tmp/rm1 && rm /tmp/rm1 && ls /tmp/rm1"]
    ),
    ("rm-missing", ["rm", "/tmp/nothing"]),
    ("rm-f", ["rm", "-f", "/tmp/nothing"]),
    (
        "rm-r",
        [
            "sh",
            "-c",
            "mkdir -p /tmp/rr/a/b && touch /tmp/rr/a/b/f && rm -r /tmp/rr && ls /tmp/rr"
        ]
    ),
    (
        "cp",
        ["sh", "-c", "cp /bb/words.txt /tmp/cp1 && cat /tmp/cp1"]
    ),
    (
        "cp-r",
        [
            "sh",
            "-c",
            "cp -r /bb/tree /tmp/cpt && find /tmp/cpt | sort"
        ]
    ),
    (
        "cp-a",
        [
            "sh",
            "-c",
            "cp -a /bb/hello.txt /tmp/cpa && ls -l --full-time /tmp/cpa | cut -d' ' -f1-3,5-"
        ]
    ),
    (
        "mv",
        [
            "sh",
            "-c",
            "echo x > /tmp/mv1 && mv /tmp/mv1 /tmp/mv2 && cat /tmp/mv2 && ls /tmp/mv1"
        ]
    ),
    (
        "mv-dir",
        [
            "sh",
            "-c",
            "mkdir /tmp/md1 && touch /tmp/md1/f && mv /tmp/md1 /tmp/md2 && ls /tmp/md2"
        ]
    ),
    (
        "ln",
        [
            "sh",
            "-c",
            "echo data > /tmp/l1 && ln /tmp/l1 /tmp/l2 && stat -c '%h' /tmp/l1 && cat /tmp/l2"
        ]
    ),
    (
        "ln-s",
        [
            "sh",
            "-c",
            "ln -s /bb/hello.txt /tmp/sl && cat /tmp/sl && readlink /tmp/sl"
        ]
    ),
    (
        "unlink",
        ["sh", "-c", "touch /tmp/ul && unlink /tmp/ul && ls /tmp/ul"]
    ),
    (
        "chmod",
        [
            "sh",
            "-c",
            "touch /tmp/cm && chmod 751 /tmp/cm && stat -c '%a %A' /tmp/cm"
        ]
    ),
    (
        "chmod-sym",
        [
            "sh",
            "-c",
            "touch /tmp/cs && chmod u+x,g-r,o=w /tmp/cs && stat -c '%a' /tmp/cs"
        ]
    ),
    (
        "truncate",
        [
            "sh",
            "-c",
            "truncate -s 100 /tmp/tr1 && stat -c '%s' /tmp/tr1"
        ]
    ),
    (
        "install",
        [
            "sh",
            "-c",
            "install -m 640 /bb/hello.txt /tmp/ins && stat -c '%a %s' /tmp/ins"
        ]
    ),
    (
        "tee",
        ["sh", "-c", "echo teed | tee /tmp/tee1 && cat /tmp/tee1"]
    ),
    ("sync", ["sync"]),
    // The shell.
    ("sh-exit", ["sh", "-c", "exit 3"]),
    ("sh-status", ["sh", "-c", "false; echo $?; true; echo $?"]),
    (
        "sh-vars",
        ["sh", "-c", "a=1; b=${a}2; echo $a $b ${c:-dflt} ${#b}"]
    ),
    (
        "sh-arith",
        ["sh", "-c", "echo $((3*4+1)) $((7%3)) $((1<<4))"]
    ),
    (
        "sh-for",
        ["sh", "-c", "for i in a b c; do echo item $i; done"]
    ),
    (
        "sh-while",
        [
            "sh",
            "-c",
            "i=0; while [ $i -lt 3 ]; do echo $i; i=$((i+1)); done"
        ]
    ),
    (
        "sh-until",
        [
            "sh",
            "-c",
            "i=3; until [ $i -eq 0 ]; do printf '%d ' $i; i=$((i-1)); done; echo"
        ]
    ),
    (
        "sh-func",
        ["sh", "-c", "f() { echo \"f:$1\"; return 4; }; f x; echo $?"]
    ),
    (
        "sh-case",
        [
            "sh",
            "-c",
            "for w in apple kiwi; do case $w in a*) echo A;; *) echo other;; esac; done"
        ]
    ),
    (
        "sh-pipe",
        [
            "sh",
            "-c",
            "echo one two three | tr ' ' '\\n' | sort -r | head -n 2"
        ]
    ),
    (
        "sh-redirect",
        [
            "sh",
            "-c",
            "echo a > /tmp/rd; echo b >> /tmp/rd; cat < /tmp/rd; echo err 1>&2 2>/dev/null"
        ]
    ),
    (
        "sh-stderr",
        ["sh", "-c", "ls /bb/nothing 2>&1; echo status=$?"]
    ),
    (
        "sh-heredoc",
        ["sh", "-c", "cat <<EOF\nline1 $((1+1))\nline2\nEOF"]
    ),
    (
        "sh-heredoc-quoted",
        ["sh", "-c", "cat <<'EOF'\n$HOME `no`\nEOF"]
    ),
    (
        "sh-subshell",
        ["sh", "-c", "x=1; (x=2; echo in $x); echo out $x"]
    ),
    (
        "sh-cmdsub",
        ["sh", "-c", "echo [$(echo sub)] [`echo tick`]"]
    ),
    (
        "sh-and-or",
        [
            "sh",
            "-c",
            "true && echo yes; false || echo no; false && echo never"
        ]
    ),
    (
        "sh-set-e",
        ["sh", "-c", "set -e; echo before; false; echo after"]
    ),
    (
        "sh-trap-exit",
        ["sh", "-c", "trap 'echo bye' EXIT; echo hi"]
    ),
    (
        "sh-trap-signal",
        [
            "sh",
            "-c",
            "trap 'echo got TERM' TERM; kill -TERM $$; echo after"
        ]
    ),
    ("sh-kill-self", ["sh", "-c", "kill -9 $$"]),
    ("sh-background", ["sh", "-c", "sleep 0 & wait; echo waited"]),
    (
        "sh-wait-status",
        ["sh", "-c", "sh -c 'exit 5' & wait $!; echo $?"]
    ),
    (
        "sh-read",
        ["sh", "-c", "echo 'a b c' | { read x y; echo \"$x|$y\"; }"]
    ),
    (
        "sh-getopts",
        [
            "sh",
            "-c",
            "set -- -a -b val rest; while getopts ab: o; do echo $o=$OPTARG; done"
        ]
    ),
    (
        "sh-umask",
        [
            "sh",
            "-c",
            "umask; umask 077; umask; touch /tmp/um; stat -c %a /tmp/um"
        ]
    ),
    ("sh-ulimit", ["sh", "-c", "ulimit -n; ulimit -c"]),
    (
        "sh-cd",
        [
            "sh",
            "-c",
            "cd /bb/tree && pwd && cd .. && pwd && cd - >/dev/null && pwd"
        ]
    ),
    (
        "sh-type",
        ["sh", "-c", "type cat; type echo; command -v nothing"]
    ),
    ("sh-script", ["sh", "/bb/script.sh", "arg1"]),
    (
        "sh-script-exec",
        ["sh", "-c", "/bb/script.sh x y; echo status=$?"]
    ),
    ("sh-noperm", ["sh", "-c", "/bb/noperm; echo status=$?"]),
    ("sh-notfound", ["sh", "-c", "/bb/nothing; echo status=$?"]),
    ("sh-notexec", ["sh", "-c", "/bb/hello.txt; echo status=$?"]),
    ("sh-xargs", ["sh", "-c", "echo a b c | xargs -n1 echo item"]),
    (
        "sh-xargs-sh",
        [
            "sh",
            "-c",
            "printf '1\\n2\\n' | xargs -I{} sh -c 'echo got {}'"
        ]
    ),
    ("sh-timeout", ["timeout", "5", "echo", "quick"]),
    ("sh-env-assign", ["sh", "-c", "FOO=bar env | grep FOO"]),
    (
        "sh-export",
        ["sh", "-c", "export Q=exported; sh -c 'echo $Q'"]
    ),
    ("sh-exec", ["sh", "-c", "exec echo replaced"]),
    (
        "sh-date",
        ["date", "-u", "-d", "@86400", "+%Y-%m-%d %H:%M:%S"]
    ),
    ("sh-kill-list", ["kill", "-l", "9"]),
    // Files: errors of the name syscalls, permissions, times, ownership.
    ("err-rm-dir", ["rm", "/bb"]),
    ("err-rmdir-file", ["rmdir", "/bb/hello.txt"]),
    ("err-mkdir-under-file", ["mkdir", "/bb/hello.txt/x"]),
    ("err-cat-under-file", ["cat", "/bb/hello.txt/x"]),
    ("err-ln-exists", ["ln", "/bb/hello.txt", "/bb/words.txt"]),
    ("err-ln-dir", ["ln", "/bb/tree", "/tmp/dirlink"]),
    ("err-mv-missing", ["mv", "/tmp/none", "/tmp/none2"]),
    (
        "err-mv-into-self",
        [
            "sh",
            "-c",
            "mkdir -p /tmp/mi/a && mv /tmp/mi /tmp/mi/a/b; echo status=$?"
        ]
    ),
    (
        "err-cp-into-self",
        [
            "sh",
            "-c",
            "mkdir -p /tmp/ci/a && cp -r /tmp/ci /tmp/ci/a; echo status=$?"
        ]
    ),
    (
        "err-symlink-loop",
        [
            "sh",
            "-c",
            "ln -s /tmp/lp2 /tmp/lp1 && ln -s /tmp/lp1 /tmp/lp2 && cat /tmp/lp1; echo status=$?"
        ]
    ),
    ("err-dangling", ["cat", "/bb/tree/dangling"]),
    (
        "err-long-name",
        [
            "sh",
            "-c",
            "n=$(printf 'a%.0s' $(seq 1 300)); touch /tmp/$n; echo status=$?"
        ]
    ),
    (
        "err-not-dir-cd",
        ["sh", "-c", "cd /bb/hello.txt; echo status=$?"]
    ),
    (
        "err-open-dir-write",
        ["sh", "-c", "echo x > /bb; echo status=$?"]
    ),
    (
        "mv-over",
        [
            "sh",
            "-c",
            "echo a > /tmp/mo1; echo b > /tmp/mo2; mv /tmp/mo1 /tmp/mo2; cat /tmp/mo2; ls /tmp/mo1"
        ]
    ),
    (
        "mv-dir-over",
        [
            "sh",
            "-c",
            "mkdir /tmp/mdo1 /tmp/mdo2; touch /tmp/mdo1/f; mv /tmp/mdo1 /tmp/mdo2; ls -R /tmp/mdo2"
        ]
    ),
    (
        "mv-dir-nonempty",
        [
            "sh",
            "-c",
            "mkdir -p /tmp/mdn1 /tmp/mdn2/x; mv /tmp/mdn1 /tmp/mdn2; echo status=$?; ls /tmp/mdn2"
        ]
    ),
    (
        "mv-cross",
        [
            "sh",
            "-c",
            "mkdir -p /tmp/mc/a /tmp/mc/b && touch /tmp/mc/a/f && mv /tmp/mc/a/f /tmp/mc/b/g && ls -R /tmp/mc"
        ]
    ),
    (
        "mv-dir-cross",
        [
            "sh",
            "-c",
            "mkdir -p /tmp/mdc/a/s /tmp/mdc/b && mv /tmp/mdc/a/s /tmp/mdc/b/t && ls -R /tmp/mdc && stat -c '%h' /tmp/mdc/a /tmp/mdc/b"
        ]
    ),
    (
        "mv-noreplace",
        [
            "sh",
            "-c",
            "touch /tmp/mn1 /tmp/mn2; mv -n /tmp/mn1 /tmp/mn2; ls /tmp/mn1 /tmp/mn2"
        ]
    ),
    (
        "rename-self",
        [
            "sh",
            "-c",
            "touch /tmp/rs; mv /tmp/rs /tmp/rs; echo status=$?"
        ]
    ),
    (
        "rename-hardlinks",
        [
            "sh",
            "-c",
            "touch /tmp/hl1; ln /tmp/hl1 /tmp/hl2; mv /tmp/hl1 /tmp/hl2; ls /tmp/hl1 /tmp/hl2; echo status=$?"
        ]
    ),
    (
        "touch-times",
        [
            "sh",
            "-c",
            "touch -d @1000 /tmp/tt && stat -c '%X %Y' /tmp/tt && touch -a -d @2000 /tmp/tt && stat -c '%X %Y' /tmp/tt && touch -m -d @3000 /tmp/tt && stat -c '%X %Y' /tmp/tt"
        ]
    ),
    (
        "touch-ref",
        [
            "sh",
            "-c",
            "touch -d @777 /tmp/tr_ref && touch -r /tmp/tr_ref /tmp/tr_new && stat -c '%X %Y' /tmp/tr_new"
        ]
    ),
    (
        "touch-no-create",
        ["sh", "-c", "touch -c /tmp/tnc; ls /tmp/tnc; echo status=$?"]
    ),
    (
        "touch-dir",
        [
            "sh",
            "-c",
            "mkdir /tmp/td && touch -d @4242 /tmp/td && stat -c '%Y' /tmp/td"
        ]
    ),
    (
        "touch-symlink",
        [
            "sh",
            "-c",
            "ln -s hello.txt /tmp/ts && touch -h -d @99 /tmp/ts && stat -c '%Y' /tmp/ts && stat -L -c '%Y' /tmp/ts"
        ]
    ),
    (
        "ctime-changes",
        [
            "sh",
            "-c",
            "touch -d @10 /tmp/ct; a=$(stat -c %Z /tmp/ct); chmod 600 /tmp/ct; b=$(stat -c %Z /tmp/ct); [ $a != $b ] && echo changed"
        ]
    ),
    (
        "chown",
        [
            "sh",
            "-c",
            "touch /tmp/co && chown 5:6 /tmp/co && stat -c '%u:%g' /tmp/co && chown 7 /tmp/co && stat -c '%u:%g' /tmp/co && chgrp 8 /tmp/co && stat -c '%u:%g' /tmp/co"
        ]
    ),
    (
        "chown-suid",
        [
            "sh",
            "-c",
            "touch /tmp/cs2 && chmod 6755 /tmp/cs2 && stat -c %a /tmp/cs2 && chown 1:1 /tmp/cs2 && stat -c %a /tmp/cs2"
        ]
    ),
    (
        "chmod-modes",
        [
            "sh",
            "-c",
            "touch /tmp/cm2 && for m in 000 7777 644 4755 2755 1777; do chmod $m /tmp/cm2; stat -c '%a %A' /tmp/cm2; done"
        ]
    ),
    (
        "chmod-recursive",
        [
            "sh",
            "-c",
            "cp -r /bb/tree /tmp/crt && chmod -R 700 /tmp/crt && ls -lR /tmp/crt | cut -c1-10"
        ]
    ),
    (
        "chmod-symlink",
        [
            "sh",
            "-c",
            "ln -s hello.txt /tmp/chs; chmod 600 /tmp/chs; stat -L -c %a /tmp/chs; stat -c %a /tmp/chs"
        ]
    ),
    (
        "mkdir-modes",
        [
            "sh",
            "-c",
            "umask 027; mkdir /tmp/mm1; mkdir -m 1777 /tmp/mm2; mkdir -m 2750 /tmp/mm3; stat -c '%a' /tmp/mm1 /tmp/mm2 /tmp/mm3"
        ]
    ),
    (
        "mkdir-sgid-inherit",
        [
            "sh",
            "-c",
            "mkdir /tmp/sg && chmod 2775 /tmp/sg && chown 0:9 /tmp/sg && mkdir /tmp/sg/d && touch /tmp/sg/f && stat -c '%a %g' /tmp/sg/d /tmp/sg/f"
        ]
    ),
    (
        "dir-sizes",
        [
            "sh",
            "-c",
            "mkdir /tmp/ds && touch /tmp/ds/a /tmp/ds/b && stat -c '%s %h' /tmp/ds && rm /tmp/ds/a && stat -c '%s %h' /tmp/ds && mkdir /tmp/ds/x && stat -c '%s %h' /tmp/ds"
        ]
    ),
    (
        "hardlink-counts",
        [
            "sh",
            "-c",
            "touch /tmp/h1 && ln /tmp/h1 /tmp/h2 && ln /tmp/h2 /tmp/h3 && stat -c %h /tmp/h1 && rm /tmp/h2 && stat -c %h /tmp/h1 /tmp/h3"
        ]
    ),
    (
        "symlink-chain",
        [
            "sh",
            "-c",
            "ln -s hello.txt /tmp/sc1 && ln -s sc1 /tmp/sc2 && ln -s sc2 /tmp/sc3 && cat /tmp/sc3 && readlink -f /tmp/sc3 && readlink /tmp/sc3 && ls -l /tmp/sc3 | cut -c1-10"
        ]
    ),
    (
        "symlink-relative-dir",
        [
            "sh",
            "-c",
            "cd /bb/tree && ln -s a/b /tmp/rel && ls /tmp/rel && cd /tmp/rel && pwd -P"
        ]
    ),
    (
        "unlink-open-file",
        [
            "sh",
            "-c",
            "echo keep > /tmp/uo; exec 3< /tmp/uo; rm /tmp/uo; cat <&3; ls /tmp/uo; echo status=$?"
        ]
    ),
    (
        "cwd-removed",
        [
            "sh",
            "-c",
            "mkdir /tmp/cr && cd /tmp/cr && rmdir /tmp/cr; pwd; ls; echo status=$?; touch f; echo status=$?"
        ]
    ),
    (
        "append-write",
        [
            "sh",
            "-c",
            "echo 1 > /tmp/ap; echo 2 >> /tmp/ap; echo 3 >> /tmp/ap; cat /tmp/ap; wc -c < /tmp/ap"
        ]
    ),
    (
        "trunc-write",
        [
            "sh",
            "-c",
            "echo longer > /tmp/tw; echo s > /tmp/tw; cat /tmp/tw; wc -c < /tmp/tw"
        ]
    ),
    (
        "read-write-fd",
        [
            "sh",
            "-c",
            "echo abcdef > /tmp/rw; exec 3<> /tmp/rw; read -n 3 x <&3; echo $x; echo XY >&3; exec 3>&-; cat /tmp/rw"
        ]
    ),
    (
        "dd-seek",
        [
            "sh",
            "-c",
            "dd if=/dev/zero of=/tmp/dds bs=1 count=0 seek=5000 2>/dev/null; stat -c %s /tmp/dds; dd if=/bb/hello.txt of=/tmp/dds bs=1 seek=4990 conv=notrunc 2>/dev/null; stat -c '%s %b' /tmp/dds; tail -c 10 /tmp/dds"
        ]
    ),
    (
        "sparse",
        [
            "sh",
            "-c",
            "dd if=/bb/hello.txt of=/tmp/sp bs=4096 seek=100 2>/dev/null; stat -c '%s %b' /tmp/sp; md5sum < /tmp/sp"
        ]
    ),
    (
        "cp-big",
        [
            "sh",
            "-c",
            "dd if=/dev/zero bs=1024 count=300 2>/dev/null | tr '\\0' 'x' > /tmp/big && cp /tmp/big /tmp/big2 && cmp /tmp/big /tmp/big2 && stat -c %s /tmp/big2 && md5sum < /tmp/big2"
        ]
    ),
    (
        "seq-pipe-big",
        [
            "sh",
            "-c",
            "seq 1 20000 | md5sum; seq 1 20000 | wc -l; seq 1 20000 | tail -n 1"
        ]
    ),
    (
        "yes-pipe-big",
        ["sh", "-c", "yes abcdefghi | head -c 300000 | md5sum"]
    ),
    (
        "cat-big-pipe",
        [
            "sh",
            "-c",
            "seq 1 30000 > /tmp/seqf; cat /tmp/seqf | cat | cat | wc -c"
        ]
    ),
    (
        "cat-file-to-file",
        [
            "sh",
            "-c",
            "seq 1 30000 > /tmp/seqf2; cat /tmp/seqf2 > /tmp/seqf3; cmp /tmp/seqf2 /tmp/seqf3; echo status=$?"
        ]
    ),
    (
        "tee-append",
        [
            "sh",
            "-c",
            "echo a | tee /tmp/te >/dev/null; echo b | tee -a /tmp/te >/dev/null; cat /tmp/te"
        ]
    ),
    (
        "sort-big",
        [
            "sh",
            "-c",
            "seq 1 5000 | sort -rn | head -n 3; seq 1 5000 | sort | md5sum"
        ]
    ),
    (
        "gzip-roundtrip",
        [
            "sh",
            "-c",
            "seq 1 5000 | gzip -c | gunzip | md5sum; seq 1 5000 | gzip -9 | wc -c"
        ]
    ),
    (
        "bzip2-roundtrip",
        ["sh", "-c", "seq 1 5000 | bzip2 -c | bunzip2 | md5sum"]
    ),
    (
        "xz-roundtrip",
        ["sh", "-c", "seq 1 5000 | xz -c | unxz | md5sum"]
    ),
    (
        "tar-roundtrip",
        [
            "sh",
            "-c",
            "tar cf /tmp/t.tar -C /bb tree && tar tf /tmp/t.tar | sort && mkdir /tmp/tx && tar xf /tmp/t.tar -C /tmp/tx && find /tmp/tx | sort | head -n 4 && ls -l --full-time /tmp/tx/tree/e.txt | cut -d' ' -f1-3,5-"
        ]
    ),
    (
        "tar-verbose",
        ["sh", "-c", "tar cvf /dev/null -C /bb tree 2>&1 | sort"]
    ),
    (
        "cpio-roundtrip",
        [
            "sh",
            "-c",
            "cd /bb/tree && find . | sort | cpio -o -H newc 2>/dev/null | cpio -it 2>/dev/null | head -n 4"
        ]
    ),
    (
        "diff-u",
        [
            "sh",
            "-c",
            "printf 'a\nb\nc\n' > /tmp/d1; printf 'a\nx\nc\n' > /tmp/d2; diff -u /tmp/d1 /tmp/d2 | tail -n +3; echo status=$?"
        ]
    ),
    (
        "patch",
        [
            "sh",
            "-c",
            "printf 'a\nb\nc\n' > /tmp/p1; printf 'a\nx\nc\n' > /tmp/p2; diff -u /tmp/p1 /tmp/p2 > /tmp/p.diff; patch /tmp/p1 < /tmp/p.diff; cat /tmp/p1"
        ]
    ),
    ("bc", ["sh", "-c", "echo '2^100' | bc"]),
    ("dc", ["sh", "-c", "echo '2 100 ^ p' | dc"]),
    ("factor", ["factor", "360360", "97"]),
    (
        "sed-i",
        [
            "sh",
            "-c",
            "printf 'one\ntwo\n' > /tmp/si; sed -i 's/o/0/g' /tmp/si; cat /tmp/si"
        ]
    ),
    (
        "sed-inplace-link",
        [
            "sh",
            "-c",
            "printf 'x\n' > /tmp/sl1; ln -s sl1 /tmp/sl2; sed -i 's/x/y/' /tmp/sl2; cat /tmp/sl1; ls -l /tmp/sl2 | cut -c1-10"
        ]
    ),
    (
        "awk-script",
        [
            "awk",
            "BEGIN { for (i = 1; i <= 5; i++) s += i * i; printf \"%d %s\\n\", s, substr(\"abcdef\", 2, 3) }"
        ]
    ),
    (
        "awk-getline",
        [
            "awk",
            "BEGIN { while ((getline line < \"/bb/words.txt\") > 0) n += length(line); print n }"
        ]
    ),
    (
        "find-newer",
        [
            "sh",
            "-c",
            "touch -d @1 /tmp/fn1; touch -d @2 /tmp/fn2; find /tmp -maxdepth 1 -newer /tmp/fn1 -name 'fn*'"
        ]
    ),
    (
        "find-size-perm",
        [
            "sh",
            "-c",
            "find /bb -maxdepth 1 -type f -size -20c -perm -u=r | sort"
        ]
    ),
    (
        "find-delete",
        [
            "sh",
            "-c",
            "mkdir -p /tmp/fd/a/b && touch /tmp/fd/a/b/f /tmp/fd/g && find /tmp/fd -depth -delete; ls /tmp/fd; echo status=$?"
        ]
    ),
    (
        "find-print0-xargs",
        [
            "sh",
            "-c",
            "find /bb/tree -name '*.txt' -print0 | sort -z | tr '\\0' ' '; echo"
        ]
    ),
    ("env-i", ["sh", "-c", "env -i A=1 B=2 env | sort"]),
    ("sh-ppid", ["sh", "-c", "echo $PPID $UID $EUID"]),
    (
        "sh-fd-dup",
        [
            "sh",
            "-c",
            "exec 3>&1; echo to-three >&3; exec 4>&3; echo to-four >&4; exec 3>&- 4>&-; echo done"
        ]
    ),
    (
        "sh-fd-inherit",
        [
            "sh",
            "-c",
            "exec 5> /tmp/fi; sh -c 'echo child >&5'; exec 5>&-; cat /tmp/fi"
        ]
    ),
    (
        "sh-cloexec",
        [
            "sh",
            "-c",
            "exec 6< /bb/hello.txt; ls /bb/nothing 2>/dev/null; cat <&6"
        ]
    ),
    (
        "sh-sigpipe",
        ["sh", "-c", "yes | head -n 1; echo ${PIPESTATUS:-na}"]
    ),
    (
        "sh-kill-child",
        ["sh", "-c", "sleep 30 & p=$!; kill $p; wait $p; echo $?"]
    ),
    (
        "sh-kill-9-child",
        ["sh", "-c", "sleep 30 & p=$!; kill -9 $p; wait $p; echo $?"]
    ),
    (
        "sh-trap-usr1",
        [
            "sh",
            "-c",
            "trap 'echo usr1' USR1; kill -USR1 $$; echo done"
        ]
    ),
    (
        "sh-trap-int-ignored",
        ["sh", "-c", "trap '' INT; kill -INT $$; echo survived"]
    ),
    (
        "sh-trap-chld",
        [
            "sh",
            "-c",
            "trap 'echo chld' CHLD; sleep 0; sleep 0; echo end"
        ]
    ),
    (
        "sh-subshell-exit",
        [
            "sh",
            "-c",
            "(exit 4); echo $?; (kill -TERM $BASHPID 2>/dev/null; true); echo ok"
        ]
    ),
    (
        "sh-wait-multiple",
        [
            "sh",
            "-c",
            "(sleep 0; exit 3) & (sleep 0; exit 5) & wait; echo $?"
        ]
    ),
    (
        "sh-nested-pipes",
        [
            "sh",
            "-c",
            "seq 1 10 | (read a; read b; echo $a $b; cat) | tail -n 2"
        ]
    ),
    (
        "sh-pipe-status",
        ["sh", "-c", "false | true; echo $?; true | false; echo $?"]
    ),
    (
        "sh-bg-output",
        ["sh", "-c", "(sleep 0; echo bg) & wait; echo fg"]
    ),
    (
        "sh-umask-file",
        [
            "sh",
            "-c",
            "umask 0; touch /tmp/u0; umask 0777; touch /tmp/u1; stat -c %a /tmp/u0 /tmp/u1"
        ]
    ),
    (
        "sh-ulimit-fsize",
        [
            "sh",
            "-c",
            "ulimit -f 1; dd if=/dev/zero of=/tmp/lim bs=1024 count=10 2>&1; echo status=$?; stat -c %s /tmp/lim"
        ]
    ),
    (
        "sh-ulimit-nofile",
        [
            "sh",
            "-c",
            "ulimit -n 8; for i in 1 2 3 4 5 6 7 8 9; do eval \"exec $((i+2))< /bb/hello.txt\" 2>/dev/null || { echo failed at $i; break; }; done"
        ]
    ),
    (
        "sh-readonly",
        ["sh", "-c", "readonly X=1; X=2; echo status=$?"]
    ),
    (
        "sh-set-u",
        ["sh", "-c", "set -u; echo $UNDEFINED; echo after"]
    ),
    ("sh-printf-e", ["sh", "-c", "printf '%s\\n' 'a b' c"]),
    ("sh-eval", ["sh", "-c", "x='echo evaled'; eval \"$x\""]),
    (
        "sh-glob",
        [
            "sh",
            "-c",
            "cd /bb && echo *.txt && echo tree/*/ && echo nomatch*"
        ]
    ),
    (
        "sh-glob-bracket",
        ["sh", "-c", "cd /bb/tree && echo [a-e]* ?.txt"]
    ),
    ("sh-tilde", ["sh", "-c", "echo ~ ~/x"]),
    (
        "sh-getopts-error",
        ["sh", "-c", "set -- -z; getopts a o 2>&1; echo status=$?"]
    ),
    (
        "sh-time-less",
        [
            "sh",
            "-c",
            "i=0; while [ $i -lt 200 ]; do i=$((i+1)); done; echo $i"
        ]
    ),
    (
        "sh-fork-many",
        [
            "sh",
            "-c",
            "i=0; while [ $i -lt 50 ]; do ( : ) ; /bin/true; i=$((i+1)); done; echo forked $i"
        ]
    ),
    (
        "sh-large-env",
        [
            "sh",
            "-c",
            "export BIG=$(seq 1 800 | tr '\\n' x); sh -c 'echo ${#BIG}'"
        ]
    ),
    ("sh-read-stdin", ["sh", "-c", "read x; echo got=$x"]),
    (
        "sh-exec-fail",
        ["sh", "-c", "exec /bb/nothing; echo not-reached"]
    ),
    (
        "sh-exit-in-pipe",
        ["sh", "-c", "echo a | { read x; exit 6; }; echo $?"]
    ),
    ("sleep-small", ["sleep", "0.01"]),
    ("usleep", ["usleep", "1000"]),
    ("uname-r", ["uname", "-r"]),
    ("hostname", ["hostname"]),
    ("nproc", ["nproc"]),
    ("stat-fs", ["stat", "-f", "-c", "%T %S %n", "/"]),
    (
        "stat-devices",
        [
            "stat",
            "-c",
            "%F %a %u %g %t %T %n",
            "/dev/null",
            "/dev/console"
        ]
    ),
    ("ls-dev", ["ls", "/dev"]),
    (
        "ls-tmp-empty",
        [
            "sh",
            "-c",
            "ls -la /tmp/nonexistent-dir 2>&1; echo status=$?"
        ]
    ),
    ("readlink-missing", ["readlink", "/bb/nothing"]),
    ("realpath-missing", ["realpath", "/bb/nothing/x"]),
    ("realpath-e", ["realpath", "-e", "/bb/tree/../tree/link"]),
    (
        "mktemp",
        [
            "sh",
            "-c",
            "f=$(mktemp /tmp/mkXXXXXX) && [ -f $f ] && echo made && d=$(mktemp -d /tmp/mkdXXXXXX) && [ -d $d ] && echo madedir; case $f in /tmp/mk??????) echo shape;; esac"
        ]
    ),
    (
        "shuf-count",
        [
            "sh",
            "-c",
            "seq 1 100 | shuf | sort -n | md5sum; seq 1 10 | shuf -n 3 | wc -l"
        ]
    ),
    (
        "awk-rand",
        [
            "awk",
            "BEGIN { srand(1); a = rand(); srand(1); b = rand(); print (a == b), (a < 1) }"
        ]
    ),
    (
        "sort-random-count",
        ["sh", "-c", "seq 1 50 | sort -R | wc -l"]
    ),
    ("od-random", ["sh", "-c", "head -c 16 /dev/urandom | wc -c"]),
    (
        "dev-zero-null",
        [
            "sh",
            "-c",
            "head -c 5 /dev/zero | od -An -tx1; echo x > /dev/null; cat /dev/null | wc -c"
        ]
    ),
    (
        "dev-full",
        ["sh", "-c", "echo x > /dev/full; echo status=$?"]
    ),
    (
        "console-write",
        ["sh", "-c", "echo to-console > /dev/console; echo status=$?"]
    ),
];

/// Process output of one command.
pub(super) struct Outcome {
    /// `exit` status or `signal` number.
    pub(super) ended: Ended,
    pub(super) kept: [u8; KEEP_MAX],
    pub(super) len: usize,
    pub(super) dropped: usize,
}

#[derive(Clone, Copy)]
pub(super) enum Ended {
    Exit(i32),
    Signal(i32),
    Other(i32),
    Lost,
}

impl core::fmt::Display for Ended {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::Exit(n) => write!(f, "exit={n}"),
            Self::Signal(n) => write!(f, "signal={n}"),
            Self::Other(n) => write!(f, "status={n:#x}"),
            Self::Lost => f.write_str("lost"),
        }
    }
}

/// `WIFEXITED` / `WIFSIGNALED` of a wait status.
pub(super) fn decode(status: i32) -> Ended {
    match (status & 0x7f, (status >> 8) & 0xff) {
        (0, code) => Ended::Exit(code),
        (signal, _) if signal != 0x7f && status & 0x80 == 0 => Ended::Signal(signal),
        _ => Ended::Other(status),
    }
}

/// `argv`/`envp` pointer arrays for `execve`, built on the child's stack: `strings` holds the NUL
/// terminated copies. The command lists stay far below both bounds (checked by the caller).
struct Vector {
    strings: [u8; 2048],
    pointers: [usize; 40],
}

impl Vector {
    /// Appends `words` to the strings and their addresses to the pointer array (no terminator).
    fn push<'a>(&mut self, at: &mut usize, n: &mut usize, words: impl Iterator<Item = &'a str>) {
        for word in words {
            self.pointers[*n] = self.strings.as_ptr().wrapping_add(*at).expose_provenance();
            self.strings[*at..*at + word.len()].copy_from_slice(word.as_bytes());
            *at += word.len() + 1;
            *n += 1;
        }
    }
}

/// What to `execve` in a forked child: the NUL terminated path of the program, its `argv` and the
/// environment (the group's fixed words, then `extra`).
pub(super) struct Exec<'a> {
    pub(super) program: &'a [u8],
    pub(super) argv: &'a [&'a str],
    pub(super) env: &'a [&'a str],
    pub(super) extra_env: &'a [&'a str],
    /// Raw output bytes kept (at most [`KEEP_MAX`]); the rest is counted and dropped.
    pub(super) keep: usize,
}

fn exec_command(exec: &Exec<'_>, null: usize) -> ! {
    let mut v = Vector {
        strings: [0; 2048],
        pointers: [0; 40],
    };
    let (mut at, mut n) = (0, 0);
    v.push(&mut at, &mut n, exec.argv.iter().copied());
    n += 1; // argv terminator
    let envp_at = n;
    v.push(
        &mut at,
        &mut n,
        exec.env.iter().chain(exec.extra_env).copied(),
    );
    let (argv, envp) = (
        v.pointers.as_ptr().expose_provenance(),
        v.pointers
            .as_ptr()
            .wrapping_add(envp_at)
            .expose_provenance(),
    );
    // stdin = /dev/null; the guard against a hang.
    let _ = sys(Sysno::dup2, &[null, 0]);
    let _ = sys(Sysno::alarm, &[GUARD_SECONDS]);
    let _ = sys(Sysno::execve, &[addr(exec.program), argv, envp]);
    // The program of the initramfs is missing: report it as a distinct status.
    die(127)
}

/// Runs one command, its stdout and stderr on one pipe read to the end.
pub(super) fn run_one(exec: &Exec<'_>, null: usize) -> Outcome {
    let mut fds = [0u32; 2];
    let _ = sys(Sysno::pipe2, &[addr_mut(&mut fds), 0]);
    let (rd, wr) = (fds[0] as usize, fds[1] as usize);
    let pid = spawn(|| {
        let _ = sys(Sysno::dup2, &[wr, 1]);
        let _ = sys(Sysno::dup2, &[wr, 2]);
        let _ = sys(Sysno::close, &[rd]);
        let _ = sys(Sysno::close, &[wr]);
        exec_command(exec, null)
    });
    let _ = sys(Sysno::close, &[wr]);
    let mut out = Outcome {
        ended: Ended::Lost,
        kept: [0; KEEP_MAX],
        len: 0,
        dropped: 0,
    };
    let mut scratch = [0u8; 256];
    loop {
        match sys(Sysno::read, &[rd, addr_mut(&mut scratch), scratch.len()]) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let room = exec.keep - out.len;
                let take = n.min(room);
                out.kept[out.len..out.len + take].copy_from_slice(&scratch[..take]);
                out.len += take;
                out.dropped += n - take;
            }
        }
    }
    let _ = sys(Sysno::close, &[rd]);
    if pid != usize::MAX {
        let (reaped, status) = wait4(pid as isize, 0);
        if reaped == Ok(pid) {
            out.ended = decode(status);
        }
    }
    out
}

/// `\n`, `\t`, `\\` and `\"` as escapes, other non-printable bytes as `\xHH`.
fn escape(bytes: &[u8], line: &mut impl core::fmt::Write) {
    for &b in bytes {
        let _ = match b {
            b'\n' => line.write_str("\\n"),
            b'\t' => line.write_str("\\t"),
            b'\\' => line.write_str("\\\\"),
            b'"' => line.write_str("\\\""),
            0x20..=0x7e => line.write_char(char::from(b)),
            _ => write!(line, "\\x{b:02x}"),
        };
    }
}

/// A result line, written with one `write(2)`: up to `4 * KEEP` bytes of escapes and the framing.
struct Wide {
    buf: [u8; 4 * KEEP_MAX + 256],
    len: usize,
}

impl core::fmt::Write for Wide {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let n = s.len().min(self.buf.len() - 1 - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}

/// The result line of one command, written with one `write(2)`:
/// `init: test <group>.<label> exit=<n>|signal=<n> out="<escaped output>"` (+ ` +<dropped>`).
pub(super) fn report(group: &str, label: &str, out: &Outcome) {
    let mut line = Wide {
        buf: [0; 4 * KEEP_MAX + 256],
        len: 0,
    };
    let _ = write!(line, "init: test {group}.{label} {} out=\"", out.ended);
    escape(&out.kept[..out.len], &mut line);
    let _ = line.write_char('"');
    if out.dropped > 0 {
        let _ = write!(line, " +{}", out.dropped);
    }
    line.buf[line.len] = b'\n';
    let _ = sys(Sysno::write, &[1, addr(&line.buf), line.len + 1]);
}

pub fn run() -> bool {
    let (mut passed, mut failed) = (0u32, 0u32);
    // The null device and the sole stdin of the children: /dev holds only /dev/console at boot.
    let _ = sys(
        Sysno::mknod,
        &[addr(b"/dev/null\0"), 0o20_666, (1 << 8) | 3],
    );
    let null = sys(Sysno::open, &[addr(b"/dev/null\0"), O_RDWR, 0]).unwrap_or(usize::MAX);
    for cmd in COMMANDS {
        let exec = Exec {
            program: BUSYBOX,
            argv: cmd.argv,
            env: &ENVP,
            extra_env: &[],
            keep: KEEP,
        };
        let out = run_one(&exec, null);
        report("busybox", cmd.label, &out);
        // A command whose child could not be reaped is a failure of the runner itself.
        if matches!(out.ended, Ended::Lost) {
            failed += 1;
        } else {
            passed += 1;
        }
    }
    random_checks(&mut passed, &mut failed);
    emit(format_args!(
        "init: tests busybox passed={passed} failed={failed}"
    ));
    failed == 0
}

/// `getrandom` where entropy is needed (the CPU of this group has a hardware generator): sizes
/// around the key and block lengths, the flags that succeed, a partial copy, two draws differing.
fn random_checks(passed: &mut u32, failed: &mut u32) {
    let mut check = |name: &str, ok: bool, got: &dyn core::fmt::Debug| {
        if ok {
            *passed += 1;
            emit(format_args!("init: test busybox.getrandom-{name} ok"));
        } else {
            *failed += 1;
            emit(format_args!(
                "init: test busybox.getrandom-{name} FAIL got={got:?}"
            ));
        }
    };
    let mut buf = [0u8; 300];
    let get = |buf: &mut [u8], len: usize, flags: usize| {
        sys(Sysno::getrandom, &[addr_mut(buf), len, flags])
    };
    for len in [1usize, 5, 31, 32, 33, 63, 64, 65, 255, 300] {
        let got = get(&mut buf, len, 0);
        let mut name = Name::default();
        let _ = write!(name, "{len}");
        check(name.as_str(), got == Ok(len), &got);
    }
    for (name, flags) in [("nonblock", 1), ("random", 2), ("insecure", 4)] {
        let got = get(&mut buf, 16, flags);
        check(name, got == Ok(16), &got);
    }
    let _ = get(&mut buf, 300, 0);
    let zeroes = buf.iter().filter(|&&b| b == 0).count();
    check("fills", zeroes < 30, &zeroes);
    let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
    let _ = get(&mut a, 32, 0);
    let _ = get(&mut b, 32, 0);
    check("differs", a != b, &"equal");
    // A partial copy: the buffer ends where the mapping does (a page whose successor is unmapped).
    let page = sys(Sysno::mmap, &[0, 8192, 3, 0x22, usize::MAX, 0]).unwrap_or(0);
    let _ = sys(Sysno::munmap, &[page + 4096, 4096]);
    let got = sys(Sysno::getrandom, &[page + 4096 - 10, 100, 0]);
    check("partial", got == Ok(10), &got);
    let got = sys(Sysno::getrandom, &[page + 4096, 100, 0]);
    check("nothing-copied", got == Err(Errno::EFAULT), &got);
    // `import_ubuf` clamps the length to MAX_RW_COUNT before `access_ok`: a huge request at a buffer
    // low enough that the clamped range stays below TASK_SIZE_MAX is a partial copy up to the
    // unmapped page, not EFAULT (the `mmap` area above is too close to the top for that).
    let low = 0x2000_0000;
    let got = sys(
        Sysno::mmap,
        &[low, 8192, 3, 0x22 | 0x10_0000, usize::MAX, 0],
    );
    if got == Ok(low) {
        let _ = sys(Sysno::munmap, &[low + 4096, 4096]);
        let got = sys(Sysno::getrandom, &[low, 1 << 62, 0]);
        check("clamp-before-access-ok", got == Ok(4096), &got);
        let got = sys(Sysno::getrandom, &[low, 0x7fff_f000 + 1, 0]);
        check("clamp-just-over", got == Ok(4096), &got);
        let _ = sys(Sysno::munmap, &[low, 4096]);
    } else {
        check("clamp-before-access-ok", false, &got);
        check("clamp-just-over", false, &got);
    }
    let _ = sys(Sysno::munmap, &[page, 4096]);
}

/// A short buffer for a check name.
#[derive(Default)]
struct Name([u8; 16], usize);

impl Name {
    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.0[..self.1]).unwrap_or("")
    }
}

impl core::fmt::Write for Name {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let n = s.len().min(self.0.len() - self.1);
        self.0[self.1..self.1 + n].copy_from_slice(&s.as_bytes()[..n]);
        self.1 += n;
        Ok(())
    }
}
