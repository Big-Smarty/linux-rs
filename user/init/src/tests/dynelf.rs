// SPDX-License-Identifier: GPL-2.0-only
//! `dynelf` group (`-- dynrun`): dynamically linked Linux programs and the ELF loader's interpreter
//! and `ET_DYN` paths (`fs/binfmt_elf.c` `load_elf_binary`, `load_elf_interp`). Three parts, all
//! run unchanged on the pinned Linux 6.18.57 (`xtask/oracle/expected.tsv` holds that output) and on
//! this kernel:
//!
//! 1. The host's glibc programs (coreutils, bash, grep, sed, find, gawk, ...: `xtask::fixture`
//!    copies them, their shared objects and the loader `ld-linux-x86-64.so.2` into a generated
//!    initramfs module at build time and never commits them) run one by one like the `busybox`
//!    group: a forked child with stdout and stderr on one pipe, the result line names how it ended
//!    and the escaped output. Every system call the loader, glibc and the programs make is compared
//!    through what the programs do with the answers.
//! 2. Synthetic images built here (a PIE with an interpreter, an `ET_EXEC` with one, a program
//!    loader without one, alignment, holes, bss) whose code, a few machine-code bytes, writes its
//!    auxiliary vector and `brk(0)` to stdout and sleeps; the parent reports both and the child's
//!    `/proc/<pid>/maps`, so the addresses `load_elf_binary` picks are compared too.
//! 3. The errno order of `execve` for a bad interpreter (`ENOENT`, `EACCES`, `ELIBBAD`, `EIO`,
//!    `ENOEXEC`) and the death by `SIGSEGV` of an exec that fails after the point of no return.
//!
//! The auxiliary vector is compared without the values of `AT_HWCAP` and `AT_MINSIGSTKSZ` (CPUID
//! of the machine the group runs on; the `xstate` group checks the latter against the XSAVE area)
//! and without `AT_RSEQ_FEATURE_SIZE`/`AT_RSEQ_ALIGN`: the reference
//! kernel has `CONFIG_RSEQ=y`, the declared configuration of this kernel `n`
//! (`kernel/src/config.rs`); the runner removes those two entries from `LD_SHOW_AUXV` output and
//! from its own dump. Inode numbers in `maps` lines are masked: they are not part of the contract.

use core::fmt::Write as _;

use syscalls::{Errno, Sysno};

use super::busybox::{Ended, Exec, KEEP_MAX, Outcome, report, run_one};
use super::proc::{spawn, wait4};
use super::{
    PAGE, Probe, R, T, addr, addr_mut, all_bytes, die, emit, mapped, mmap, peek, poke, sys,
};

const ENVP: [&str; 3] = ["PATH=/usr/bin", "HOME=/", "LC_ALL=C"];
const O_RDWR: usize = 2;
const O_WRONLY: usize = 1;
const O_CREAT: usize = 0o100;
const O_TRUNC: usize = 0o1000;
const SIGKILL: usize = 9;

/// One program run: the label of its line, the program, `argv` and extra environment words.
struct Cmd {
    label: &'static str,
    program: &'static str,
    argv: &'static [&'static str],
    env: &'static [&'static str],
}

macro_rules! cmds {
    ($(($label:literal, $program:expr, [$($arg:literal),+ $(,)?] $(, [$($env:literal),*])?)),+ $(,)?) => {
        &[$(Cmd { label: $label, program: $program, argv: &[$($arg),+], env: &[$($($env),*)?] }),+]
    };
}

const LD: &str = "/lib64/ld-linux-x86-64.so.2";

/// The command list. A label is unique and stable: the `expected.tsv` row is keyed by it.
const COMMANDS: &[Cmd] = cmds![
    // Coreutils with a fixed output.
    ("true", "/usr/bin/true", ["true"]),
    ("false", "/usr/bin/false", ["false"]),
    ("echo", "/usr/bin/echo", ["echo", "hello", "world"]),
    ("echo-n", "/usr/bin/echo", ["echo", "-n", "no newline"]),
    ("echo-e", "/usr/bin/echo", ["echo", "-e", "a\\tb\\\\c\\x41"]),
    (
        "printf",
        "/usr/bin/printf",
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
    ("seq", "/usr/bin/seq", ["seq", "1", "5"]),
    ("seq-step", "/usr/bin/seq", ["seq", "10", "-3", "0"]),
    ("expr", "/usr/bin/expr", ["expr", "2", "+", "3", "*", "4"]),
    ("factor", "/usr/bin/factor", ["factor", "360", "97"]),
    (
        "basename",
        "/usr/bin/basename",
        ["basename", "/a/b/c.txt", ".txt"]
    ),
    ("dirname", "/usr/bin/dirname", ["dirname", "/a/b/c.txt"]),
    ("uname", "/usr/bin/uname", ["uname", "-s", "-m", "-n", "-o"]),
    ("id", "/usr/bin/id", ["id"]),
    ("id-un", "/usr/bin/id", ["id", "-un"]),
    ("whoami", "/usr/bin/whoami", ["whoami"]),
    ("pwd", "/usr/bin/pwd", ["pwd"]),
    ("env", "/usr/bin/env", ["env"]),
    (
        "env-set",
        "/usr/bin/env",
        ["env", "-i", "A=1", "/usr/bin/printenv", "A"]
    ),
    (
        "printenv",
        "/usr/bin/printenv",
        ["printenv", "HOME", "PATH"]
    ),
    ("tty", "/usr/bin/tty", ["tty"]),
    ("nproc", "/usr/bin/nproc", ["nproc"]),
    ("sleep-0", "/usr/bin/sleep", ["sleep", "0"]),
    (
        "date",
        "/usr/bin/date",
        ["date", "-u", "-d", "@1000000000", "+%F %T"]
    ),
    // Reading files.
    (
        "cat",
        "/usr/bin/cat",
        ["cat", "/bb/hello.txt", "/bb/csv.txt"]
    ),
    ("cat-missing", "/usr/bin/cat", ["cat", "/bb/nothing"]),
    ("cat-dir", "/usr/bin/cat", ["cat", "/bb"]),
    (
        "wc",
        "/usr/bin/wc",
        ["wc", "/bb/words.txt", "/bb/lines.txt"]
    ),
    ("wc-l", "/usr/bin/wc", ["wc", "-l", "/bb/lines.txt"]),
    (
        "head",
        "/usr/bin/head",
        ["head", "-n", "2", "/bb/lines.txt"]
    ),
    (
        "head-c",
        "/usr/bin/head",
        ["head", "-c", "7", "/bb/words.txt"]
    ),
    (
        "tail",
        "/usr/bin/tail",
        ["tail", "-n", "2", "/bb/lines.txt"]
    ),
    (
        "tail-c",
        "/usr/bin/tail",
        ["tail", "-c", "6", "/bb/words.txt"]
    ),
    ("sort", "/usr/bin/sort", ["sort", "/bb/lines.txt"]),
    ("sort-n", "/usr/bin/sort", ["sort", "-n", "/bb/nums.txt"]),
    ("sort-rn", "/usr/bin/sort", ["sort", "-rn", "/bb/nums.txt"]),
    ("sort-u", "/usr/bin/sort", ["sort", "-u", "/bb/lines.txt"]),
    ("tac", "/usr/bin/tac", ["tac", "/bb/nums.txt"]),
    ("rev", "/usr/bin/rev", ["rev", "/bb/words.txt"]),
    ("nl", "/usr/bin/nl", ["nl", "/bb/csv.txt"]),
    (
        "cut",
        "/usr/bin/cut",
        ["cut", "-d,", "-f2,3", "/bb/csv.txt"]
    ),
    (
        "paste",
        "/usr/bin/paste",
        ["paste", "/bb/nums.txt", "/bb/nums.txt"]
    ),
    (
        "fold",
        "/usr/bin/fold",
        ["fold", "-w", "10", "/bb/words.txt"]
    ),
    (
        "od",
        "/usr/bin/od",
        ["od", "-A", "x", "-t", "x1", "-N", "48", "/bb/bin.dat"]
    ),
    ("base64", "/usr/bin/base64", ["base64", "/bb/hello.txt"]),
    (
        "cmp",
        "/usr/bin/cmp",
        ["cmp", "/bb/hello.txt", "/bb/words.txt"]
    ),
    (
        "diff",
        "/usr/bin/diff",
        ["diff", "/bb/nums.txt", "/bb/lines.txt"]
    ),
    (
        "comm",
        "/usr/bin/comm",
        ["comm", "/bb/lines.txt", "/bb/lines.txt"]
    ),
    // The file system.
    ("ls", "/usr/bin/ls", ["ls", "/bb/tree"]),
    ("ls-a", "/usr/bin/ls", ["ls", "-a", "/bb/tree"]),
    ("ls-l", "/usr/bin/ls", ["ls", "-l", "/bb"]),
    ("ls-ln", "/usr/bin/ls", ["ls", "-ln", "/bb/tree"]),
    (
        "ls-ld",
        "/usr/bin/ls",
        ["ls", "-ld", "/bb", "/bb/hello.txt", "/bb/tree/link"]
    ),
    ("ls-R", "/usr/bin/ls", ["ls", "-R", "/bb/tree"]),
    ("ls-missing", "/usr/bin/ls", ["ls", "/bb/nothing"]),
    (
        "stat",
        "/usr/bin/stat",
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
    ("stat-missing", "/usr/bin/stat", ["stat", "/bb/nothing"]),
    (
        "readlink",
        "/usr/bin/readlink",
        ["readlink", "/bb/tree/link"]
    ),
    (
        "realpath",
        "/usr/bin/realpath",
        ["realpath", "/bb/tree/link"]
    ),
    (
        "test-file",
        "/usr/bin/test",
        ["test", "-f", "/bb/hello.txt"]
    ),
    (
        "test-dir-missing",
        "/usr/bin/test",
        ["test", "-d", "/bb/nothing"]
    ),
    (
        "find",
        "/usr/bin/find",
        ["find", "/bb/tree", "-name", "*.txt"]
    ),
    (
        "find-type",
        "/usr/bin/find",
        ["find", "/bb/tree", "-type", "d"]
    ),
    ("du", "/usr/bin/du", ["du", "-a", "/bb/tree"]),
    // Text tools of other packages (more shared objects).
    ("grep", "/usr/bin/grep", ["grep", "apple", "/bb/lines.txt"]),
    (
        "grep-c",
        "/usr/bin/grep",
        ["grep", "-c", "an", "/bb/lines.txt"]
    ),
    ("grep-r", "/usr/bin/grep", ["grep", "-r", "dd", "/bb/tree"]),
    (
        "grep-E",
        "/usr/bin/grep",
        ["grep", "-E", "^(ban|ch).*y$", "/bb/lines.txt"]
    ),
    (
        "sed-s",
        "/usr/bin/sed",
        ["sed", "s/apple/PEAR/", "/bb/lines.txt"]
    ),
    (
        "sed-n",
        "/usr/bin/sed",
        ["sed", "-n", "2,3p", "/bb/lines.txt"]
    ),
    (
        "awk-sum",
        "/usr/bin/gawk",
        ["gawk", "-F,", "NR>1{s+=$2} END{print s}", "/bb/csv.txt"]
    ),
    (
        "awk-printf",
        "/usr/bin/gawk",
        ["gawk", "BEGIN{printf \"%d %s %.1f\\n\", 7, \"x\", 2.5}"]
    ),
    (
        "xargs",
        "/usr/bin/xargs",
        ["xargs", "-n", "1", "/usr/bin/echo", "x", "/bb/hello.txt"]
    ),
    // bash.
    (
        "bash-echo",
        "/usr/bin/bash",
        ["bash", "-c", "echo hello from bash"]
    ),
    (
        "bash-pipeline",
        "/usr/bin/bash",
        [
            "bash",
            "-c",
            "cat /bb/lines.txt | sort | uniq -c | sort -rn | head -n 2"
        ]
    ),
    (
        "bash-loop",
        "/usr/bin/bash",
        [
            "bash",
            "-c",
            "for i in 1 2 3; do echo n$i; done; i=0; while [ $i -lt 3 ]; do i=$((i+1)); done; echo $i"
        ]
    ),
    (
        "bash-function",
        "/usr/bin/bash",
        [
            "bash",
            "-c",
            "f() { echo \"f:$1:$#\"; return 3; }; f a b; echo rc=$?"
        ]
    ),
    (
        "bash-heredoc",
        "/usr/bin/bash",
        ["bash", "-c", "cat <<EOF\nline $((6*7))\n$HOME\nEOF"]
    ),
    (
        "bash-subshell",
        "/usr/bin/bash",
        [
            "bash",
            "-c",
            "x=1; (x=2; echo in$x); echo out$x; echo $(echo sub)"
        ]
    ),
    (
        "bash-trap",
        "/usr/bin/bash",
        [
            "bash",
            "-c",
            "trap 'echo bye' EXIT; trap 'echo usr1' USR1; kill -USR1 $$; echo done"
        ]
    ),
    (
        "bash-bg",
        "/usr/bin/bash",
        [
            "bash",
            "-c",
            "(exit 5) & wait $!; echo rc=$?; sleep 0 & wait; echo all"
        ]
    ),
    (
        "bash-redirect",
        "/usr/bin/bash",
        [
            "bash",
            "-c",
            "exec 3>/tmp/bash-r; echo to3 >&3; exec 3>&-; cat /tmp/bash-r; echo err >&2 2>/dev/null; rm /tmp/bash-r"
        ]
    ),
    (
        "bash-array",
        "/usr/bin/bash",
        [
            "bash",
            "-c",
            "a=(x y z); declare -A m=([k]=v); echo ${#a[@]} ${a[1]} ${m[k]}; [[ abc =~ ^a(.)c$ ]] && echo ${BASH_REMATCH[1]}"
        ]
    ),
    (
        "bash-glob",
        "/usr/bin/bash",
        ["bash", "-c", "cd /bb; echo *.txt; echo tree/*"]
    ),
    (
        "bash-read",
        "/usr/bin/bash",
        [
            "bash",
            "-c",
            "while IFS=, read -r a b c; do echo \"[$a][$b][$c]\"; done < /bb/csv.txt"
        ]
    ),
    (
        "bash-set-e",
        "/usr/bin/bash",
        ["bash", "-c", "set -e; echo before; false; echo after"]
    ),
    (
        "bash-missing",
        "/usr/bin/bash",
        [
            "bash",
            "-c",
            "/usr/bin/nothing-here; echo rc=$?; nothing-either; echo rc=$?"
        ]
    ),
    (
        "bash-umask",
        "/usr/bin/bash",
        ["bash", "-c", "umask; umask 027; umask; type -t cd ls echo"]
    ),
    (
        "sh-echo",
        "/usr/bin/sh",
        ["sh", "-c", "echo posix; echo $0"]
    ),
    ("bash-script", "/bb/script.sh", ["/bb/script.sh", "arg1"]),
    (
        "bash-files",
        "/usr/bin/bash",
        [
            "bash",
            "-c",
            "cd /tmp && mkdir -p d/e && echo hi > d/e/f && cp -r d d2 && mv d2 d3 && ln -s d/e/f lnk && chmod 600 d/e/f && ls -lR d3 | grep -c f; ls d/e; stat -c %a d/e/f; readlink lnk; rm -rf d d3 lnk; ls /tmp"
        ]
    ),
    (
        "bash-gzip",
        "/usr/bin/bash",
        [
            "bash",
            "-c",
            "gzip -c /bb/words.txt | gzip -dc | cmp - /bb/words.txt && echo gz-same; tar -cf - -C /bb tree | tar -tf - | sort"
        ]
    ),
    (
        "bash-dd",
        "/usr/bin/bash",
        [
            "bash",
            "-c",
            "dd if=/bb/bin.dat bs=16 skip=2 count=1 status=none | od -A n -t x1; yes | head -n 3"
        ]
    ),
    // More of coreutils: colours (libcap), limits, file system facts, a preloaded library.
    (
        "ls-color",
        "/usr/bin/ls",
        ["ls", "--color=always", "-l", "/bb"]
    ),
    ("stat-f", "/usr/bin/stat", ["stat", "-f", "-c", "%T", "/"]),
    (
        "bash-ulimit",
        "/usr/bin/bash",
        [
            "bash",
            "-c",
            "for o in n s c l t d f m v q e r R; do echo $o $(ulimit -$o); done"
        ]
    ),
    (
        "stdbuf",
        "/usr/bin/stdbuf",
        ["stdbuf", "-o0", "/usr/bin/echo", "unbuffered"]
    ),
    (
        "setsid",
        "/usr/bin/setsid",
        ["setsid", "-w", "/usr/bin/echo", "session"]
    ),
    ("sleep-short", "/usr/bin/sleep", ["sleep", "0.05"]),
    // Larger workloads: many processes, big files, many directory entries, pcre2's JIT.
    (
        "sort-many",
        "/usr/bin/bash",
        [
            "bash",
            "-c",
            "seq 1 3000 | sort -rn | head -n 3; seq 1 3000 | sort | tail -n 2; seq 1 3000 | wc -l"
        ]
    ),
    (
        "bash-forks",
        "/usr/bin/bash",
        [
            "bash",
            "-c",
            "for i in $(seq 1 60); do (exit $((i % 5))); done; echo done; s=0; for i in $(seq 1 40); do s=$((s + $(echo $i | wc -c))); done; echo $s"
        ]
    ),
    (
        "tar-roundtrip",
        "/usr/bin/bash",
        [
            "bash",
            "-c",
            "cd /tmp && rm -rf t1 t2 && mkdir t1 t2 && cp -a /bb/tree t1/ && tar -cf t.tar -C t1 tree && tar -xf t.tar -C t2 && ls -lR t2 | head -n 12; stat -c '%a %Y %n' t2/tree/exec.sh; rm -rf t1 t2 t.tar"
        ]
    ),
    (
        "sed-i",
        "/usr/bin/bash",
        [
            "bash",
            "-c",
            "printf 'a\\nb\\nc\\n' > /tmp/s.txt && sed -i 's/b/B/' /tmp/s.txt && cat /tmp/s.txt && rm /tmp/s.txt"
        ]
    ),
    (
        "grep-P",
        "/usr/bin/grep",
        ["grep", "-P", "^\\w+an\\w*$", "/bb/lines.txt"]
    ),
    (
        "awk-array",
        "/usr/bin/gawk",
        [
            "gawk",
            "BEGIN { for (i = 0; i < 1000; i++) a[i] = i * i; s = 0; for (k in a) s += a[k]; print s; print length(a); print substr(\"abcdef\", 2, 3), toupper(\"x\") }"
        ]
    ),
    (
        "find-exec",
        "/usr/bin/find",
        [
            "find", "/bb/tree", "-name", "*.txt", "-exec", "cat", "{}", ";"
        ]
    ),
    (
        "ls-many",
        "/usr/bin/bash",
        [
            "bash",
            "-c",
            "cd /tmp && mkdir lsd && cd lsd && for i in $(seq 1 300); do : > f$i; done; ls | wc -l; ls | head -n 3; ls -1U | wc -l; cd ..; rm -rf lsd"
        ]
    ),
    (
        "dd-big",
        "/usr/bin/bash",
        [
            "bash",
            "-c",
            "dd if=/dev/zero of=/tmp/z bs=1M count=4 2>&1 | head -n 2; ls -l /tmp/z | cut -d' ' -f5; rm /tmp/z"
        ]
    ),
    (
        "cat-big",
        "/usr/bin/bash",
        [
            "bash",
            "-c",
            "cat /usr/lib/libc.so.6 | wc -c; cmp /usr/lib/libc.so.6 /usr/lib/libc.so.6 && echo same; cat /usr/lib/libc.so.6 /usr/lib/libm.so.6 > /tmp/big; ls -l /tmp/big | cut -d' ' -f5; rm /tmp/big"
        ]
    ),
    (
        "gzip-big",
        "/usr/bin/bash",
        [
            "bash",
            "-c",
            "gzip -c /usr/lib/libc.so.6 | gzip -dc | cmp - /usr/lib/libc.so.6 && echo same"
        ]
    ),
    // Python 3.14 (the interpreter, libpython and a few standard modules).
    (
        "python-print",
        "/usr/bin/python3",
        ["python3", "-I", "-S", "-B", "-c", "print(1 + 1)"]
    ),
    (
        "python-sys",
        "/usr/bin/python3",
        [
            "python3",
            "-I",
            "-S",
            "-B",
            "-c",
            "import sys; print(sys.platform, sys.byteorder, sys.maxsize, sys.argv, sys.flags.isolated)",
            "a1",
            "a2"
        ]
    ),
    (
        "python-math",
        "/usr/bin/python3",
        [
            "python3",
            "-I",
            "-S",
            "-B",
            "-c",
            "import math; print(math.sqrt(2), math.factorial(20), math.gcd(84, 36), math.pi)"
        ]
    ),
    (
        "python-re",
        "/usr/bin/python3",
        [
            "python3",
            "-I",
            "-S",
            "-B",
            "-c",
            "import re; print(re.sub(r'(\\d+)', r'<\\1>', 'a1b22c333'), re.findall(r'\\w+', 'hi there you'))"
        ]
    ),
    (
        "python-json",
        "/usr/bin/python3",
        [
            "python3",
            "-I",
            "-S",
            "-B",
            "-c",
            "import json; print(json.dumps({'b': [1, 2, {'c': None}], 'a': True}, sort_keys=True), json.loads('[1, 2.5, \"x\"]'))"
        ]
    ),
    (
        "python-collections",
        "/usr/bin/python3",
        [
            "python3",
            "-I",
            "-S",
            "-B",
            "-c",
            "import collections; c = collections.Counter('abracadabra'); print(sorted(c.items()), collections.OrderedDict(a=1))"
        ]
    ),
    (
        "python-os",
        "/usr/bin/python3",
        [
            "python3",
            "-I",
            "-S",
            "-B",
            "-c",
            "import os; print(sorted(os.listdir('/bb/tree')), os.path.getsize('/bb/hello.txt'), os.getcwd(), os.getuid(), os.environ['HOME'], os.uname().sysname)"
        ]
    ),
    (
        "python-files",
        "/usr/bin/python3",
        [
            "python3",
            "-I",
            "-S",
            "-B",
            "-c",
            "f = open('/bb/hello.txt'); print(repr(f.read())); f.close(); g = open('/tmp/py.txt', 'w'); g.write('x' * 5000); g.close(); h = open('/tmp/py.txt', 'rb'); print(len(h.read())); h.close(); import os; os.remove('/tmp/py.txt')"
        ]
    ),
    (
        "python-fork",
        "/usr/bin/python3",
        [
            "python3",
            "-I",
            "-S",
            "-B",
            "-c",
            "import os\nr, w = os.pipe()\npid = os.fork()\nif pid == 0:\n    os.write(w, b'child')\n    os._exit(7)\nos.close(w)\nprint(os.read(r, 10), os.waitpid(pid, 0)[1] >> 8)"
        ]
    ),
    (
        "python-signal",
        "/usr/bin/python3",
        [
            "python3",
            "-I",
            "-S",
            "-B",
            "-c",
            "import os, signal\nseen = []\nsignal.signal(signal.SIGUSR1, lambda n, f: seen.append(n))\nos.kill(os.getpid(), signal.SIGUSR1)\nprint(seen)"
        ]
    ),
    (
        "python-exit",
        "/usr/bin/python3",
        ["python3", "-I", "-S", "-B", "-c", "raise SystemExit(3)"]
    ),
    (
        "python-traceback",
        "/usr/bin/python3",
        ["python3", "-I", "-S", "-B", "-c", "1 / 0"]
    ),
    (
        "python-sum",
        "/usr/bin/python3",
        [
            "python3",
            "-I",
            "-S",
            "-B",
            "-c",
            "print(sum(i * i for i in range(300000)), len(str(2 ** 5000)))"
        ]
    ),
    // The loader itself and its environment.
    ("ld-list", LD, ["ld.so", "--list", "/usr/bin/true"]),
    ("ld-list-ls", LD, ["ld.so", "--list", "/usr/bin/ls"]),
    ("ld-verify", LD, ["ld.so", "--verify", "/usr/bin/true"]),
    ("ld-run", LD, ["ld.so", "/usr/bin/echo", "via", "ld.so"]),
    (
        "ld-library-path",
        LD,
        [
            "ld.so",
            "--library-path",
            "/nonexistent:/usr/lib",
            "/usr/bin/true"
        ]
    ),
    ("ld-no-file", LD, ["ld.so", "/nonexistent"]),
    ("ld-not-elf", LD, ["ld.so", "/bb/hello.txt"]),
    (
        "ld-trace",
        "/usr/bin/ls",
        ["ls", "/bb/hello.txt"],
        ["LD_TRACE_LOADED_OBJECTS=1"]
    ),
    (
        "ld-preload-missing",
        "/usr/bin/true",
        ["true"],
        ["LD_PRELOAD=/nonexistent.so"]
    ),
    (
        "ld-show-auxv",
        "/usr/bin/true",
        ["true"],
        ["LD_SHOW_AUXV=1"]
    ),
    (
        "ld-bind-now",
        "/usr/bin/ls",
        ["ls", "/bb/hello.txt"],
        ["LD_BIND_NOW=1"]
    ),
    (
        "ld-library-path-env",
        "/usr/bin/ls",
        ["ls", "/bb/hello.txt"],
        ["LD_LIBRARY_PATH=/nonexistent"]
    ),
    ("maps-cat", "/usr/bin/cat", ["cat", "/proc/self/maps"]),
    ("maps-ld", LD, ["ld.so", "/usr/bin/cat", "/proc/self/maps"]),
    (
        "maps-bash",
        "/usr/bin/bash",
        [
            "bash",
            "-c",
            "cat /proc/self/maps | cut -d' ' -f1,2,6- | sed -n '1,40p'"
        ]
    ),
    // Programs that make threads (glibc `pthread_create`: `clone3`, a stack with a guard region
    // from `mprotect` or `madvise(MADV_GUARD_INSTALL)`, `madvise(MADV_DONTNEED)` when the stack
    // is released, futex joins, robust lists). Python's `_thread` needs no library file besides
    // the interpreter; `sort` starts threads for 128K lines or more; `xz -T` one worker per
    // block.
    (
        "python-thread",
        "/usr/bin/python3",
        [
            "python3",
            "-I",
            "-S",
            "-B",
            "-c",
            "import _thread\nlock = _thread.allocate_lock()\nlock.acquire()\nres = []\ndef work():\n    res.append(sum(range(100000)))\n    lock.release()\n_thread.start_new_thread(work, ())\nlock.acquire()\nprint(res)"
        ]
    ),
    (
        "python-threads",
        "/usr/bin/python3",
        [
            "python3",
            "-I",
            "-S",
            "-B",
            "-c",
            "import _thread\ndone = _thread.allocate_lock()\nmutex = _thread.allocate_lock()\nres = {}\nleft = [4]\ndef work(k):\n    s = sum(i * k for i in range(20000))\n    with mutex:\n        res[k] = s\n        left[0] -= 1\n        if left[0] == 0:\n            done.release()\ndone.acquire()\nfor k in (1, 2, 3, 4):\n    _thread.start_new_thread(work, (k,))\ndone.acquire()\nprint(sorted(res.items()), _thread.get_ident() != 0)"
        ]
    ),
    (
        "sort-parallel",
        "/usr/bin/bash",
        [
            "bash",
            "-c",
            "seq 1 200000 | sort -rn --parallel=2 | sed -n '1p;$p'"
        ]
    ),
    (
        "sort-parallel-four",
        "/usr/bin/bash",
        [
            "bash",
            "-c",
            "seq 1 300000 | sort -n --parallel=4 -S 16M | tail -n 2"
        ]
    ),
    (
        "xz-threads",
        "/usr/bin/bash",
        [
            "bash",
            "-c",
            "seq 1 20000 | xz -1 -T2 --block-size=16384 -c | xz -dc | wc -l"
        ]
    ),
];

fn cstr(path: &str, buf: &mut [u8; 128]) -> usize {
    buf[..path.len()].copy_from_slice(path.as_bytes());
    buf[path.len()] = 0;
    addr(buf)
}

/// `LD_SHOW_AUXV` output, normalised: the `AT_RSEQ_FEATURE_SIZE`/`AT_RSEQ_ALIGN` lines are removed
/// (see the module note) and the values of the CPU dependent entries `AT_HWCAP` and
/// `AT_MINSIGSTKSZ` become `*` (they come from the CPUID of the machine the group runs on, which
/// is not the machine the rows were recorded on). `lines` is the raw output; the result is
/// compacted in place.
fn drop_rseq_lines(out: &mut Outcome) {
    let mut masked = [0u8; KEEP_MAX];
    let mut len = 0;
    for line in out.kept[..out.len].split_inclusive(|&b| b == b'\n') {
        if line.starts_with(b"AT_RSEQ_") {
            continue;
        }
        let cpu = line.starts_with(b"AT_HWCAP:") || line.starts_with(b"AT_MINSIGSTKSZ:");
        let line = match line.iter().position(|&b| b == b':') {
            // Keep the name and the padding up to the value column.
            Some(colon) if cpu => {
                let pad = line[colon + 1..].iter().take_while(|&&b| b == b' ').count();
                let head = &line[..colon + 1 + pad];
                masked[len..len + head.len()].copy_from_slice(head);
                len += head.len();
                masked[len] = b'*';
                masked[len + 1] = b'\n';
                len += 2;
                continue;
            }
            _ => line,
        };
        masked[len..len + line.len()].copy_from_slice(line);
        len += line.len();
    }
    out.kept[..len].copy_from_slice(&masked[..len]);
    out.len = len;
}

/// Masks the inode column (the fifth) of `maps` lines when it is not zero.
fn mask_inodes(out: &mut Outcome) {
    let mut masked = [0u8; KEEP_MAX];
    let mut len = 0;
    let mut push = |bytes: &[u8]| {
        let n = bytes.len().min(KEEP_MAX - len);
        masked[len..len + n].copy_from_slice(&bytes[..n]);
        len += n;
    };
    for line in out.kept[..out.len].split_inclusive(|&b| b == b'\n') {
        let mut fields = line.splitn(6, |&b| b == b' ');
        let head: [Option<&[u8]>; 4] = [fields.next(), fields.next(), fields.next(), fields.next()];
        let (inode, rest) = (fields.next(), fields.next());
        match (head, inode, rest) {
            ([Some(a), Some(b), Some(c), Some(d)], Some(i), rest)
                if i != b"0" && !i.is_empty() && i.iter().all(u8::is_ascii_digit) =>
            {
                for field in [a, b, c, d] {
                    push(field);
                    push(b" ");
                }
                push(b"I");
                if let Some(rest) = rest {
                    push(b" ");
                    push(rest);
                }
            }
            _ => push(line),
        }
    }
    out.kept[..len].copy_from_slice(&masked[..len]);
    out.len = len;
}

fn run_commands(passed: &mut u32, failed: &mut u32, null: usize) {
    for cmd in COMMANDS {
        let mut program = [0u8; 128];
        let _ = cstr(cmd.program, &mut program);
        let exec = Exec {
            program: &program[..=cmd.program.len()],
            argv: cmd.argv,
            env: &ENVP,
            extra_env: cmd.env,
            keep: KEEP_MAX,
        };
        let mut out = run_one(&exec, null);
        if cmd.label.starts_with("ld-show") {
            drop_rseq_lines(&mut out);
        }
        if cmd.label.starts_with("maps-") {
            mask_inodes(&mut out);
        }
        report("dynelf", cmd.label, &out);
        if matches!(out.ended, Ended::Lost) {
            *failed += 1;
        } else {
            *passed += 1;
        }
    }
}

// ---- synthetic images ----------------------------------------------------------------------------

/// The probe program (x86-64 machine code, assembled once from the listing in the comment): it
/// writes its auxiliary vector (up to and including `AT_NULL`) to fd 1, then `brk(0)` as eight
/// bytes, then sleeps in `pause` forever. Position independent.
///
/// ```text
///  mov rax,[rsp]; lea rsi,[rsp+rax*8+8]; add rsi,8        ; rsi = envp
/// 1: cmp qword [rsi],0; je 2; add rsi,8; jmp 1             ; skip the environment
/// 2: add rsi,8; mov rdx,rsi                                 ; rsi = auxv
/// 3: cmp qword [rdx],0; je 4; add rdx,16; jmp 3             ; find AT_NULL
/// 4: add rdx,16; sub rdx,rsi; mov edi,1; mov eax,1; syscall ; write(1, auxv, len)
///  mov eax,12; xor edi,edi; syscall; push rax               ; brk(0)
///  mov rsi,rsp; mov edx,8; mov edi,1; mov eax,1; syscall    ; write(1, &brk, 8)
/// 5: mov eax,34; syscall; jmp 5                             ; pause()
/// ```
const PROBE: [u8; 102] = [
    0x48, 0x8b, 0x04, 0x24, 0x48, 0x8d, 0x74, 0xc4, 0x08, 0x48, 0x83, 0xc6, 0x08, 0x48, 0x83, 0x3e,
    0x00, 0x74, 0x06, 0x48, 0x83, 0xc6, 0x08, 0xeb, 0xf4, 0x48, 0x83, 0xc6, 0x08, 0x48, 0x89, 0xf2,
    0x48, 0x83, 0x3a, 0x00, 0x74, 0x06, 0x48, 0x83, 0xc2, 0x10, 0xeb, 0xf4, 0x48, 0x83, 0xc2, 0x10,
    0x48, 0x29, 0xf2, 0xbf, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x01, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xb8,
    0x0c, 0x00, 0x00, 0x00, 0x31, 0xff, 0x0f, 0x05, 0x50, 0x48, 0x89, 0xe6, 0xba, 0x08, 0x00, 0x00,
    0x00, 0xbf, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x01, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xb8, 0x22, 0x00,
    0x00, 0x00, 0x0f, 0x05, 0xeb, 0xf7,
];
/// `mov edi,42; mov eax,231; syscall`: `exit_group(42)`.
const EXIT42: [u8; 12] = [
    0xbf, 0x2a, 0x00, 0x00, 0x00, 0xb8, 0xe7, 0x00, 0x00, 0x00, 0x0f, 0x05,
];

const PT_LOAD: u32 = 1;
const PT_INTERP: u32 = 3;
const PT_GNU_STACK: u32 = 0x6474_e551;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
const ET_REL: u16 = 1;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
/// Where the code sits in the file; the interpreter string is at [`INTERP_AT`].
const CODE_AT: usize = 0x200;
const INTERP_AT: usize = 0x180;

/// One `PT_LOAD`.
#[derive(Clone, Copy)]
struct Load {
    flags: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
    memsz: u64,
    align: u64,
}

const fn load(flags: u32, offset: u64, vaddr: u64, filesz: u64, memsz: u64) -> Load {
    Load {
        flags,
        offset,
        vaddr,
        filesz,
        memsz,
        align: 0x1000,
    }
}

/// An ELF64 image in a fixed buffer: header, program table, optional interpreter string, code.
struct Image {
    buf: [u8; 0x3000],
    len: usize,
}

/// What to put in the image's `PT_INTERP`: nothing, a path, or a raw segment header edit.
#[derive(Clone, Copy)]
enum Interp<'a> {
    None,
    /// The path (a NUL is appended).
    Path(&'a [u8]),
    /// `p_filesz` and the bytes as given (no NUL appended).
    Raw(u64, &'a [u8]),
}

struct Spec<'a> {
    ty: u16,
    machine: u16,
    phentsize: u16,
    /// Virtual address of the code (`e_entry` is `entry_base + CODE_AT`).
    entry_base: u64,
    interp: Interp<'a>,
    loads: &'a [Load],
    /// Extra program headers before the loads, `(type, flags)`.
    extra: &'a [(u32, u32)],
    code: &'a [u8],
    /// File length (at least the end of the code).
    len: usize,
}

impl Spec<'_> {
    fn base(ty: u16) -> Spec<'static> {
        Spec {
            ty,
            machine: 62,
            phentsize: 56,
            entry_base: 0,
            interp: Interp::None,
            loads: &[],
            extra: &[(PT_GNU_STACK, PF_R | PF_W)],
            code: &PROBE,
            len: 0x400,
        }
    }
}

fn put(buf: &mut [u8], at: usize, bytes: &[u8]) {
    buf[at..at + bytes.len()].copy_from_slice(bytes);
}

fn build(spec: &Spec<'_>) -> Image {
    let mut img = Image {
        buf: [0; 0x3000],
        len: spec.len.max(CODE_AT + spec.code.len()),
    };
    let b = &mut img.buf;
    put(b, 0, b"\x7fELF\x02\x01\x01");
    put(b, 16, &spec.ty.to_le_bytes());
    put(b, 18, &spec.machine.to_le_bytes());
    put(b, 20, &1u32.to_le_bytes());
    put(b, 24, &(spec.entry_base + CODE_AT as u64).to_le_bytes());
    put(b, 32, &64u64.to_le_bytes());
    put(b, 52, &64u16.to_le_bytes());
    put(b, 54, &spec.phentsize.to_le_bytes());
    let mut count = 0usize;
    let mut ph =
        |b: &mut [u8], kind: u32, flags: u32, off: u64, va: u64, fsz: u64, msz: u64, al: u64| {
            let at = 64 + count * 56;
            put(b, at, &kind.to_le_bytes());
            put(b, at + 4, &flags.to_le_bytes());
            put(b, at + 8, &off.to_le_bytes());
            put(b, at + 16, &va.to_le_bytes());
            put(b, at + 24, &va.to_le_bytes());
            put(b, at + 32, &fsz.to_le_bytes());
            put(b, at + 40, &msz.to_le_bytes());
            put(b, at + 48, &al.to_le_bytes());
            count += 1;
        };
    match spec.interp {
        Interp::None => {}
        Interp::Path(path) => {
            ph(
                b,
                PT_INTERP,
                PF_R,
                INTERP_AT as u64,
                0,
                path.len() as u64 + 1,
                path.len() as u64 + 1,
                1,
            );
        }
        Interp::Raw(size, _) => ph(b, PT_INTERP, PF_R, INTERP_AT as u64, 0, size, size, 1),
    }
    for &(kind, flags) in spec.extra {
        ph(b, kind, flags, 0, 0, 0, 0, 16);
    }
    for l in spec.loads {
        ph(
            b, PT_LOAD, l.flags, l.offset, l.vaddr, l.filesz, l.memsz, l.align,
        );
    }
    put(b, 56, &(count as u16).to_le_bytes());
    match spec.interp {
        Interp::None => {}
        Interp::Path(path) => put(b, INTERP_AT, path),
        Interp::Raw(_, bytes) => put(b, INTERP_AT, bytes),
    }
    put(b, CODE_AT, spec.code);
    img
}

/// Writes `img` to `path` with mode 0755 (replacing any earlier file).
fn install(path: &str, img: &Image) -> bool {
    let mut p = [0u8; 128];
    let at = cstr(path, &mut p);
    let _ = sys(Sysno::unlink, &[at]);
    let Ok(fd) = sys(Sysno::open, &[at, O_WRONLY | O_CREAT | O_TRUNC, 0o755]) else {
        return false;
    };
    let wrote = sys(Sysno::write, &[fd, addr(&img.buf[..img.len]), img.len]);
    let _ = sys(Sysno::close, &[fd]);
    wrote == Ok(img.len)
}

fn install_text(path: &str, bytes: &[u8], mode: usize) -> bool {
    let mut p = [0u8; 128];
    let at = cstr(path, &mut p);
    let _ = sys(Sysno::unlink, &[at]);
    let Ok(fd) = sys(Sysno::open, &[at, O_WRONLY | O_CREAT | O_TRUNC, mode]) else {
        return false;
    };
    let wrote = sys(Sysno::write, &[fd, addr(bytes), bytes.len()]);
    let _ = sys(Sysno::close, &[fd]);
    wrote == Ok(bytes.len())
}

/// How an `execve` of `path` ended: `Err(errno)` when it failed, else the wait status of the
/// program (read through a close-on-exec pipe, so a successful `execve` is told from a failed one).
fn try_exec(path: &str) -> Result<i32, Errno> {
    let mut fds = [0u32; 2];
    let _ = sys(Sysno::pipe2, &[addr_mut(&mut fds), 0o2_000_000]);
    let (rd, wr) = (fds[0] as usize, fds[1] as usize);
    let mut p = [0u8; 128];
    let at = cstr(path, &mut p);
    let argv = [at, 0];
    let envp = [0usize];
    let pid = spawn(|| {
        // The program's own output goes nowhere.
        if let Ok(null) = sys(Sysno::open, &[addr(b"/dev/null\0"), O_RDWR, 0]) {
            let _ = sys(Sysno::dup2, &[null, 1]);
            let _ = sys(Sysno::dup2, &[null, 2]);
        }
        let err = sys(Sysno::execve, &[at, addr(&argv), addr(&envp)]);
        let code = match err {
            Err(e) => e.into_raw() as u32,
            Ok(_) => 0xffff,
        };
        let _ = sys(Sysno::write, &[wr, addr(&code), 4]);
        0
    });
    let _ = sys(Sysno::close, &[wr]);
    let mut code = 0u32;
    let got = sys(Sysno::read, &[rd, addr_mut(&mut code), 4]);
    let _ = sys(Sysno::close, &[rd]);
    let (_, status) = wait4(pid as isize, 0);
    match got {
        Ok(4) => Err(Errno::new(code as i32)),
        _ => Ok(status),
    }
}

/// The probe's findings, as a text for the result line: the auxiliary vector without the RSEQ
/// entries, `brk(0)` and the child's `maps` (inodes masked).
struct Probed {
    ended: Ended,
    text: Outcome,
}

fn probe(path: &str, argv0: &str, extra_env: &[&str]) -> Probed {
    let mut fds = [0u32; 2];
    let _ = sys(Sysno::pipe2, &[addr_mut(&mut fds), 0]);
    let (rd, wr) = (fds[0] as usize, fds[1] as usize);
    let mut program = [0u8; 128];
    let program_len = path.len() + 1;
    let _ = cstr(path, &mut program);
    let pid = spawn(|| {
        let _ = sys(Sysno::dup2, &[wr, 1]);
        let _ = sys(Sysno::close, &[rd]);
        let _ = sys(Sysno::close, &[wr]);
        let exec = Exec {
            program: &program[..program_len],
            argv: &[argv0],
            env: &ENVP,
            extra_env,
            keep: 0,
        };
        exec_plain(&exec)
    });
    let _ = sys(Sysno::close, &[wr]);
    let mut out = Outcome {
        ended: Ended::Lost,
        kept: [0; KEEP_MAX],
        len: 0,
        dropped: 0,
    };
    // Collect the auxiliary vector up to AT_NULL and the eight bytes of brk.
    let mut raw = [0u8; 1024];
    let mut have = 0usize;
    let mut need = usize::MAX;
    while have < need.min(raw.len()) {
        match sys(
            Sysno::read,
            &[rd, addr_mut(&mut raw[have..]), raw.len() - have],
        ) {
            Ok(0) | Err(_) => break,
            Ok(n) => have += n,
        }
        if need == usize::MAX {
            let mut k = 0;
            while (k + 1) * 16 <= have {
                if raw[k * 16..k * 16 + 8] == [0; 8] {
                    need = (k + 1) * 16 + 8;
                    break;
                }
                k += 1;
            }
        }
    }
    let _ = sys(Sysno::close, &[rd]);
    let mut text = Text::new();
    if need <= have {
        let _ = write!(text, "auxv");
        for pair in raw[..need - 8].chunks_exact(16) {
            let key = u64::from_le_bytes(pair[..8].try_into().unwrap_or([0; 8]));
            let value = u64::from_le_bytes(pair[8..].try_into().unwrap_or([0; 8]));
            // AT_RSEQ_FEATURE_SIZE, AT_RSEQ_ALIGN (see the module note); AT_HWCAP and
            // AT_MINSIGSTKSZ depend on the CPU (`drop_rseq_lines`).
            if key == 16 || key == 51 {
                let _ = write!(text, " {key}=*");
            } else if key != 27 && key != 28 && key != 0 {
                let _ = write!(text, " {key}={value:#x}");
            }
        }
        let brk = u64::from_le_bytes(raw[need - 8..need].try_into().unwrap_or([0; 8]));
        let _ = write!(text, "\nbrk={brk:#x}\n");
        let mut maps = [0u8; 4096];
        let mut name = [0u8; 64];
        let name_len = {
            let mut t = Text::new();
            let _ = write!(t, "/proc/{pid}/maps");
            name[..t.len].copy_from_slice(&t.buf[..t.len]);
            t.len
        };
        name[name_len] = 0;
        let mut size = 0;
        if let Ok(fd) = sys(Sysno::open, &[addr(&name), 0, 0]) {
            while let Ok(n) = sys(
                Sysno::read,
                &[fd, addr_mut(&mut maps[size..]), maps.len() - size],
            ) {
                if n == 0 {
                    break;
                }
                size += n;
            }
            let _ = sys(Sysno::close, &[fd]);
        }
        let n = size.min(KEEP_MAX - text.len);
        let at = text.len;
        text.buf[at..at + n].copy_from_slice(&maps[..n]);
        text.len += n;
        out.dropped = size - n;
    } else {
        let _ = write!(text, "no output have={have}");
    }
    let _ = sys(Sysno::kill, &[pid, SIGKILL]);
    let (reaped, status) = wait4(pid as isize, 0);
    if reaped == Ok(pid) {
        out.ended = super::busybox::decode(status);
    }
    out.kept[..text.len].copy_from_slice(&text.buf[..text.len]);
    out.len = text.len;
    mask_inodes(&mut out);
    Probed {
        ended: out.ended,
        text: out,
    }
}

/// `execve` with no stdin juggling (the probe's child has set its descriptors).
fn exec_plain(exec: &Exec<'_>) -> ! {
    let mut strings = [0u8; 256];
    let mut pointers = [0usize; 24];
    let (mut at, mut n) = (0, 0);
    for word in exec.argv {
        pointers[n] = strings.as_ptr().wrapping_add(at).expose_provenance();
        strings[at..at + word.len()].copy_from_slice(word.as_bytes());
        at += word.len() + 1;
        n += 1;
    }
    n += 1;
    let envp_at = n;
    for word in exec.env.iter().chain(exec.extra_env) {
        pointers[n] = strings.as_ptr().wrapping_add(at).expose_provenance();
        strings[at..at + word.len()].copy_from_slice(word.as_bytes());
        at += word.len() + 1;
        n += 1;
    }
    let argv = pointers.as_ptr().expose_provenance();
    let envp = pointers.as_ptr().wrapping_add(envp_at).expose_provenance();
    // The exit status says why the `execve` failed: 100 plus the errno.
    let code = match sys(Sysno::execve, &[addr(exec.program), argv, envp]) {
        Err(errno) => 100 + errno.into_raw() as usize,
        Ok(_) => 127,
    };
    die(code)
}

/// A small text buffer.
struct Text {
    buf: [u8; KEEP_MAX],
    len: usize,
}

impl Text {
    const fn new() -> Self {
        Self {
            buf: [0; KEEP_MAX],
            len: 0,
        }
    }
}

impl core::fmt::Write for Text {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let n = s.len().min(self.buf.len() - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}

const MAIN: &str = "/tmp/dyn-main";
const INTERP: &str = "/tmp/dyn-interp";

/// Reports one probed layout as a result line.
fn layout(label: &str, passed: &mut u32, failed: &mut u32, p: &Probed) {
    report("dynelf", label, &p.text);
    if matches!(p.ended, Ended::Lost) {
        *failed += 1;
    } else {
        *passed += 1;
    }
}

/// Programs and interpreters linked in many shapes: the layout the loader chose is the result.
fn layouts(passed: &mut u32, failed: &mut u32) {
    // A PIE (text, data with bss) and a position independent interpreter that only probes.
    let text = load(PF_R | PF_X, 0, 0, 0x400, 0x400);
    let data = load(PF_R | PF_W, 0x1010, 0x2010, 0x20, 0x3000);
    let pie = |loads: &'static [Load], interp: Interp<'static>| {
        let mut s = Spec::base(ET_DYN);
        s.interp = interp;
        s.loads = loads;
        s.len = 0x1040;
        build(&s)
    };
    static PIE_LOADS: [Load; 2] = [
        load(PF_R | PF_X, 0, 0, 0x400, 0x400),
        load(PF_R | PF_W, 0x1010, 0x2010, 0x20, 0x3000),
    ];
    let _ = (text, data);
    let interp_img = {
        let mut s = Spec::base(ET_DYN);
        s.loads = &PIE_LOADS;
        s.len = 0x1040;
        build(&s)
    };
    let ok = install(INTERP, &interp_img)
        && install(MAIN, &pie(&PIE_LOADS, Interp::Path(INTERP.as_bytes())));
    if !ok {
        *failed += 1;
        emit(format_args!("init: test dynelf.layout-setup FAIL"));
        return;
    }
    // PIE with an interpreter: bias ELF_ET_DYN_BASE, the interpreter below the stack.
    layout("pie-interp", passed, failed, &probe(MAIN, "dyn-main", &[]));

    // Main with a hole between two loads, then bss (total_mapping_size maps the hole first).
    static HOLE: [Load; 3] = [
        load(PF_R | PF_X, 0, 0, 0x400, 0x400),
        load(PF_R, 0x1000, 0x10000, 0x20, 0x20),
        load(PF_R | PF_W, 0x1010, 0x20010, 0x20, 0x100),
    ];
    let mut s = Spec::base(ET_DYN);
    s.interp = Interp::Path(INTERP.as_bytes());
    s.loads = &HOLE;
    s.len = 0x1040;
    let _ = install(MAIN, &build(&s));
    layout("pie-hole", passed, failed, &probe(MAIN, "dyn-main", &[]));

    // ET_EXEC with an interpreter (fixed address, MAP_FIXED_NOREPLACE).
    static EXEC_LOADS: [Load; 2] = [
        load(PF_R | PF_X, 0, 0x40_0000, 0x400, 0x400),
        load(PF_R | PF_W, 0x1010, 0x40_2010, 0x20, 0x2000),
    ];
    let mut s = Spec::base(ET_EXEC);
    s.interp = Interp::Path(INTERP.as_bytes());
    s.loads = &EXEC_LOADS;
    s.entry_base = 0x40_0000;
    s.len = 0x1040;
    let _ = install(MAIN, &build(&s));
    layout(
        "etexec-interp",
        passed,
        failed,
        &probe(MAIN, "dyn-main", &[]),
    );

    // ET_DYN without an interpreter (a program loader): top-down at the mmap base, brk moved.
    let mut s = Spec::base(ET_DYN);
    s.loads = &PIE_LOADS;
    s.len = 0x1040;
    let _ = install(MAIN, &build(&s));
    layout(
        "dyn-nointerp",
        passed,
        failed,
        &probe(MAIN, "dyn-main", &[]),
    );

    // ET_DYN without an interpreter whose first load starts at a page offset.
    static OFFSET: [Load; 2] = [
        load(PF_R | PF_X, 0x200, 0x200, 0x200, 0x200),
        load(PF_R | PF_W, 0x1010, 0x2010, 0x20, 0x3000),
    ];
    let mut s = Spec::base(ET_DYN);
    s.loads = &OFFSET;
    s.entry_base = 0;
    s.len = 0x1040;
    let _ = install(MAIN, &build(&s));
    layout(
        "dyn-first-offset",
        passed,
        failed,
        &probe(MAIN, "dyn-main", &[]),
    );

    // p_align 2 MiB: a loader is placed at an aligned address, a PIE below ELF_ET_DYN_BASE aligned.
    static ALIGNED: [Load; 2] = [
        Load {
            align: 0x20_0000,
            ..load(PF_R | PF_X, 0, 0, 0x400, 0x400)
        },
        Load {
            align: 0x20_0000,
            ..load(PF_R | PF_W, 0x1010, 0x20_2010, 0x20, 0x1000)
        },
    ];
    let mut s = Spec::base(ET_DYN);
    s.loads = &ALIGNED;
    s.len = 0x1040;
    let _ = install(MAIN, &build(&s));
    layout(
        "dyn-nointerp-align",
        passed,
        failed,
        &probe(MAIN, "dyn-main", &[]),
    );
    let mut s = Spec::base(ET_DYN);
    s.interp = Interp::Path(INTERP.as_bytes());
    s.loads = &ALIGNED;
    s.len = 0x1040;
    let _ = install(MAIN, &build(&s));
    layout(
        "pie-interp-align",
        passed,
        failed,
        &probe(MAIN, "dyn-main", &[]),
    );

    // The interpreter forms: ET_EXEC at a fixed address, holes, aligned, a pure-bss load.
    static INTERP_EXEC: [Load; 2] = [
        load(PF_R | PF_X, 0, 0x7000_0000, 0x400, 0x400),
        load(PF_R | PF_W, 0x1010, 0x7000_2010, 0x20, 0x1000),
    ];
    let mut s = Spec::base(ET_EXEC);
    s.loads = &INTERP_EXEC;
    s.entry_base = 0x7000_0000;
    s.len = 0x1040;
    let _ = install(INTERP, &build(&s));
    let mut s = Spec::base(ET_DYN);
    s.interp = Interp::Path(INTERP.as_bytes());
    s.loads = &PIE_LOADS;
    s.len = 0x1040;
    let _ = install(MAIN, &build(&s));
    layout("interp-exec", passed, failed, &probe(MAIN, "dyn-main", &[]));

    static INTERP_HOLE: [Load; 3] = [
        load(PF_R | PF_X, 0, 0, 0x400, 0x400),
        load(PF_R | PF_W, 0x1010, 0x8010, 0x20, 0x20),
        load(PF_R | PF_W, 0x1000, 0x30010, 0, 0x2000),
    ];
    let mut s = Spec::base(ET_DYN);
    s.loads = &INTERP_HOLE;
    s.len = 0x1040;
    let _ = install(INTERP, &build(&s));
    layout(
        "interp-hole-bss",
        passed,
        failed,
        &probe(MAIN, "dyn-main", &[]),
    );

    let mut s = Spec::base(ET_DYN);
    s.loads = &ALIGNED;
    s.len = 0x1040;
    let _ = install(INTERP, &build(&s));
    layout(
        "interp-align",
        passed,
        failed,
        &probe(MAIN, "dyn-main", &[]),
    );

    // Programs whose ET_DYN needs the stack: PT_GNU_STACK with and without PF_X.
    let mut s = Spec::base(ET_DYN);
    s.loads = &PIE_LOADS;
    s.extra = &[(PT_GNU_STACK, PF_R | PF_W | PF_X)];
    s.len = 0x1040;
    let _ = install(MAIN, &build(&s));
    layout(
        "dyn-exec-stack",
        passed,
        failed,
        &probe(MAIN, "dyn-main", &[]),
    );
    let mut s = Spec::base(ET_DYN);
    s.loads = &PIE_LOADS;
    s.extra = &[];
    s.len = 0x1040;
    let _ = install(MAIN, &build(&s));
    layout(
        "dyn-no-gnu-stack",
        passed,
        failed,
        &probe(MAIN, "dyn-main", &[]),
    );
}

/// The errno order of a bad interpreter and the exits after the point of no return.
fn errors(t: &mut T) {
    let mut s = Spec::base(ET_DYN);
    static PIE_LOADS: [Load; 1] = [load(PF_R | PF_X, 0, 0, 0x400, 0x400)];
    s.loads = &PIE_LOADS;
    s.code = &EXIT42;
    let good_interp = build(&s);
    let _ = install(INTERP, &good_interp);
    let exit_status = |status: i32| (status >> 8) & 0xff;
    let main_with = |interp: Interp<'_>| {
        let mut m = Spec::base(ET_DYN);
        m.interp = interp;
        m.loads = &PIE_LOADS;
        m.code = &EXIT42;
        let _ = install(MAIN, &build(&m));
    };
    // The happy path of the tiny pair: the interpreter ran (exit 42).
    main_with(Interp::Path(INTERP.as_bytes()));
    let got = try_exec(MAIN).map(exit_status);
    t.eq("exec-interp-runs", got, Ok(42));

    // open_exec(interpreter) errors, in open(2)'s order.
    main_with(Interp::Path(b"/tmp/no-such-interp"));
    t.eq("exec-interp-missing", try_exec(MAIN), Err(Errno::ENOENT));
    main_with(Interp::Path(b"/tmp"));
    t.eq("exec-interp-directory", try_exec(MAIN), Err(Errno::EACCES));
    let _ = install_text("/tmp/dyn-noexec", b"\x7fELF", 0o644);
    main_with(Interp::Path(b"/tmp/dyn-noexec"));
    t.eq(
        "exec-interp-not-executable",
        try_exec(MAIN),
        Err(Errno::EACCES),
    );
    main_with(Interp::Path(b"/tmp/dyn-nodir/x"));
    t.eq("exec-interp-enoent-dir", try_exec(MAIN), Err(Errno::ENOENT));
    main_with(Interp::Path(b"/tmp/dyn-main/x"));
    t.eq("exec-interp-enotdir", try_exec(MAIN), Err(Errno::ENOTDIR));
    // The interpreter string itself.
    main_with(Interp::Raw(1, b"\0"));
    t.eq("exec-interp-size-one", try_exec(MAIN), Err(Errno::ENOEXEC));
    main_with(Interp::Raw(0x1001, &[b'a'; 0x40]));
    t.eq("exec-interp-too-long", try_exec(MAIN), Err(Errno::ENOEXEC));
    main_with(Interp::Raw(8, b"/tmp/abc"));
    t.eq(
        "exec-interp-unterminated",
        try_exec(MAIN),
        Err(Errno::ENOEXEC),
    );
    main_with(Interp::Raw(2, b"x\0"));
    t.eq("exec-interp-relative", try_exec(MAIN), Err(Errno::ENOENT));
    main_with(Interp::Raw(2, b"\0\0"));
    t.eq("exec-interp-empty-path", try_exec(MAIN), Err(Errno::EACCES));
    // Shape of the interpreter file: not ELF, short, wrong machine, wrong program header size.
    let _ = install_text(
        INTERP,
        b"#!/bin/sh\n# not an elf, but long enough to fill the header buffer ....\n",
        0o755,
    );
    main_with(Interp::Path(INTERP.as_bytes()));
    t.eq("exec-interp-not-elf", try_exec(MAIN), Err(Errno::ELIBBAD));
    let _ = install_text(INTERP, b"\x7fELF\x02\x01", 0o755);
    t.eq("exec-interp-short", try_exec(MAIN), Err(Errno::EIO));
    let _ = install_text(INTERP, b"", 0o755);
    t.eq("exec-interp-empty-file", try_exec(MAIN), Err(Errno::EIO));
    let mut bad = Spec::base(ET_DYN);
    bad.loads = &PIE_LOADS;
    bad.code = &EXIT42;
    bad.machine = 3;
    let _ = install(INTERP, &build(&bad));
    t.eq("exec-interp-machine", try_exec(MAIN), Err(Errno::ELIBBAD));
    let mut bad = Spec::base(ET_DYN);
    bad.loads = &PIE_LOADS;
    bad.code = &EXIT42;
    bad.phentsize = 32;
    let _ = install(INTERP, &build(&bad));
    t.eq("exec-interp-phentsize", try_exec(MAIN), Err(Errno::ELIBBAD));
    // The interpreter's program table lies outside its file.
    let mut bad = build(&{
        let mut b = Spec::base(ET_DYN);
        b.loads = &PIE_LOADS;
        b.code = &EXIT42;
        b
    });
    bad.buf[32..40].copy_from_slice(&0x10000u64.to_le_bytes());
    let _ = install(INTERP, &bad);
    t.eq(
        "exec-interp-phdrs-outside",
        try_exec(MAIN),
        Err(Errno::ELIBBAD),
    );
    // No program header at all.
    let mut bad = build(&{
        let mut b = Spec::base(ET_DYN);
        b.loads = &PIE_LOADS;
        b.code = &EXIT42;
        b
    });
    bad.buf[56..58].copy_from_slice(&0u16.to_le_bytes());
    let _ = install(INTERP, &bad);
    t.eq("exec-interp-no-phdrs", try_exec(MAIN), Err(Errno::ELIBBAD));

    // After the point of no return a failure is SIGSEGV: wrong e_type, no PT_LOAD, bad load.
    let died = |status: i32| status & 0x7f;
    let mut bad = Spec::base(ET_REL);
    bad.loads = &PIE_LOADS;
    bad.code = &EXIT42;
    let _ = install(INTERP, &build(&bad));
    t.eq("exec-interp-type-rel", try_exec(MAIN).map(died), Ok(11));
    let mut bad = Spec::base(ET_DYN);
    bad.code = &EXIT42;
    let _ = install(INTERP, &build(&bad));
    t.eq("exec-interp-no-loads", try_exec(MAIN).map(died), Ok(11));
    static HUGE: [Load; 1] = [load(PF_R | PF_X, 0, 0, 0x400, 0x7fff_ffff_f000)];
    let mut bad = Spec::base(ET_DYN);
    bad.loads = &HUGE;
    bad.code = &EXIT42;
    let _ = install(INTERP, &build(&bad));
    t.eq("exec-interp-too-big", try_exec(MAIN).map(died), Ok(11));
    static FILESZ: [Load; 1] = [load(PF_R | PF_X, 0, 0, 0x800, 0x400)];
    let mut bad = Spec::base(ET_DYN);
    bad.loads = &FILESZ;
    bad.code = &EXIT42;
    let _ = install(INTERP, &build(&bad));
    t.eq(
        "exec-interp-filesz-over-memsz",
        try_exec(MAIN).map(died),
        Ok(11),
    );
    // The main image has no PT_LOAD: nothing is mapped (total_mapping_size is only asked for at
    // the first load), the interpreter runs.
    let mut m = Spec::base(ET_DYN);
    m.interp = Interp::Path(INTERP.as_bytes());
    m.code = &EXIT42;
    let _ = install(INTERP, &good_interp);
    let _ = install(MAIN, &build(&m));
    t.eq(
        "exec-main-no-loads-runs",
        try_exec(MAIN).map(exit_status),
        Ok(42),
    );
    // A static PIE (no interpreter) runs at the mmap base.
    let mut m = Spec::base(ET_DYN);
    m.loads = &PIE_LOADS;
    m.code = &EXIT42;
    let _ = install(MAIN, &build(&m));
    t.eq(
        "exec-static-pie-runs",
        try_exec(MAIN).map(exit_status),
        Ok(42),
    );
    // The interpreter is the program itself (loop through the same file).
    main_with(Interp::Path(MAIN.as_bytes()));
    t.eq(
        "exec-interp-is-self",
        try_exec(MAIN).map(exit_status),
        Ok(42),
    );
    // An interpreter that is a script is not an ELF interpreter (ELIBBAD), not a script run.
    let _ = install_text(
        "/tmp/dyn-script",
        b"#!/tmp/dyn-interp\n# padding so that the file is as long as an ELF header: ..........\n",
        0o755,
    );
    main_with(Interp::Path(b"/tmp/dyn-script"));
    t.eq("exec-interp-script", try_exec(MAIN), Err(Errno::ELIBBAD));
    let _ = R::Ok(0);
}

/// `clone(CLONE_CHILD_SETTID)` as glibc's `fork` makes it: the child finds its own thread id
/// where the pointer says, before it runs a line of user code; the parent's copy is untouched.
fn clone_checks(t: &mut T) {
    const SIGCHLD: usize = 17;
    const CLONE_CHILD_CLEARTID: usize = 0x20_0000;
    const CLONE_CHILD_SETTID: usize = 0x100_0000;
    let mut ctid: i32 = 0;
    let at = addr_mut(&mut ctid);
    let pid = sys(
        Sysno::clone,
        &[
            SIGCHLD | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID,
            0,
            0,
            at,
            0,
        ],
    );
    if pid == Ok(0) {
        let seen = word_at(at);
        let me = sys(Sysno::gettid, &[]).unwrap_or(usize::MAX);
        die(if usize::try_from(seen) == Ok(me) {
            0
        } else {
            1
        });
    }
    let pid = pid.unwrap_or(usize::MAX);
    let (reaped, status) = wait4(pid as isize, 0);
    t.eq(
        "sys-clone-child-settid",
        (reaped == Ok(pid), status),
        (true, 0),
    );
    t.eq("sys-clone-child-settid-parent", word_at(at), 0);
    // Without the flag the child's copy keeps the parent's value.
    let pid = sys(Sysno::clone, &[SIGCHLD, 0, 0, at, 0]);
    if pid == Ok(0) {
        die(if word_at(at) == 0 { 0 } else { 1 });
    }
    let pid = pid.unwrap_or(usize::MAX);
    let (reaped, status) = wait4(pid as isize, 0);
    t.eq(
        "sys-clone-no-settid",
        (reaped == Ok(pid), status),
        (true, 0),
    );
}

/// The `i32` at `at` (a live local of this process), read byte by byte.
fn word_at(at: usize) -> i32 {
    i32::from_le_bytes([peek(at), peek(at + 1), peek(at + 2), peek(at + 3)])
}

// ---- mremap (the call glibc's realloc makes for big blocks) ---------------------------------------

const MREMAP_MAYMOVE: usize = 1;
const MREMAP_FIXED: usize = 2;
const MREMAP_DONTUNMAP: usize = 4;
const ANON: usize = 0x22;
const NOFD: usize = usize::MAX;
const PROT_R: usize = 1;
const PROT_RW: usize = 3;
const MAP_FIXED: usize = 0x10;

fn mremap(a: usize, old: usize, new: usize, flags: usize, to: usize) -> R {
    sys(Sysno::mremap, &[a, old, new, flags, to])
}

/// A page-aligned anonymous area of `pages` pages at a fixed address with `byte + page index` in
/// the first byte of each page.
fn area(at: usize, pages: usize, prot: usize) -> usize {
    let got = mmap(at, pages * PAGE, PROT_RW, ANON | MAP_FIXED, NOFD, 0).unwrap_or(0);
    for i in 0..pages {
        poke(got + i * PAGE, 0x40 + i as u8);
    }
    if prot != PROT_RW {
        let _ = sys(Sysno::mprotect, &[got, pages * PAGE, prot]);
    }
    got
}

/// The first byte of up to four pages (zero for the unused slots).
fn tags(at: usize, pages: usize) -> [u8; 4] {
    let mut out = [0u8; 4];
    for (i, slot) in out.iter_mut().enumerate().take(pages) {
        *slot = peek(at + i * PAGE);
    }
    out
}

fn mremap_checks(t: &mut T) {
    const A: usize = 0x2000_0000;
    const B: usize = 0x3000_0000;
    // Argument errors, in `check_mremap_params` / `check_prep_vma` order.
    let a = area(A, 4, PROT_RW);
    t.eq(
        "sys-mremap-flag",
        mremap(a, PAGE, PAGE, 8, 0),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sys-mremap-fixed-needs-maymove",
        mremap(a, PAGE, PAGE, MREMAP_FIXED, B),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sys-mremap-dontunmap-needs-maymove",
        mremap(a, PAGE, PAGE, MREMAP_DONTUNMAP, B),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sys-mremap-dontunmap-resize",
        mremap(a, PAGE, 2 * PAGE, MREMAP_MAYMOVE | MREMAP_DONTUNMAP, B),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sys-mremap-unaligned",
        mremap(a + 1, PAGE, PAGE, 0, 0),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sys-mremap-zero-new",
        mremap(a, PAGE, 0, 0, 0),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sys-mremap-zero-old",
        mremap(a, 0, PAGE, 0, 0),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sys-mremap-overlap",
        mremap(
            a,
            2 * PAGE,
            2 * PAGE,
            MREMAP_MAYMOVE | MREMAP_FIXED,
            a + PAGE,
        ),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sys-mremap-unaligned-target",
        mremap(a, PAGE, PAGE, MREMAP_MAYMOVE | MREMAP_FIXED, B + 1),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sys-mremap-unmapped",
        mremap(B, PAGE, 2 * PAGE, MREMAP_MAYMOVE, 0),
        Err(Errno::EFAULT),
    );
    t.eq(
        "sys-mremap-past-the-vma",
        mremap(a, 5 * PAGE, 6 * PAGE, MREMAP_MAYMOVE, 0),
        Err(Errno::EFAULT),
    );
    t.eq(
        "sys-mremap-same-size",
        mremap(a + PAGE, PAGE, PAGE, 0, 0),
        Ok(a + PAGE),
    );
    t.eq(
        "sys-mremap-same-size-unchecked",
        mremap(a, 9 * PAGE, 9 * PAGE, 0, 0),
        Ok(a),
    );
    // Shrink: the tail goes, the head keeps its data.
    t.eq(
        "sys-mremap-shrink",
        mremap(a, 4 * PAGE, 2 * PAGE, 0, 0),
        Ok(a),
    );
    t.eq("sys-mremap-shrink-head", mapped(a, 2 * PAGE), Ok(0));
    t.eq(
        "sys-mremap-shrink-tail",
        mapped(a + 2 * PAGE, PAGE),
        Err(Errno::ENOMEM),
    );
    t.eq("sys-mremap-shrink-data", tags(a, 2), tags_of([0x40, 0x41]));
    // Grow in place: nothing is above; the new pages are zero.
    t.eq(
        "sys-mremap-grow",
        mremap(a, 2 * PAGE, 5 * PAGE, 0, 0),
        Ok(a),
    );
    t.eq(
        "sys-mremap-grow-data",
        (tags(a, 2), all_bytes(a + 2 * PAGE, 3 * PAGE, 0)),
        (tags_of([0x40, 0x41]), true),
    );
    // Only the end of a VMA can grow in place: the middle cannot, and without MAYMOVE it fails.
    t.eq(
        "sys-mremap-grow-middle",
        mremap(a, 2 * PAGE, 3 * PAGE, 0, 0),
        Err(Errno::ENOMEM),
    );
    // Blocked by the next mapping: no MAYMOVE fails, MAYMOVE relocates with the data.
    let _ = sys(Sysno::munmap, &[a, 5 * PAGE]);
    let low = area(A, 2, PROT_RW);
    let _high = area(A + 2 * PAGE, 2, PROT_R);
    t.eq(
        "sys-mremap-blocked",
        mremap(low, 2 * PAGE, 4 * PAGE, 0, 0),
        Err(Errno::ENOMEM),
    );
    // Where `mmap(NULL)` would put four pages is where the move goes.
    let top_down = mmap(0, 4 * PAGE, PROT_RW, ANON, NOFD, 0).unwrap_or(0);
    let _ = sys(Sysno::munmap, &[top_down, 4 * PAGE]);
    let moved = mremap(low, 2 * PAGE, 4 * PAGE, MREMAP_MAYMOVE, 0).unwrap_or(0);
    t.holds(
        "sys-mremap-moved",
        moved != 0 && moved != low,
        moved,
        "a new address",
    );
    t.eq(
        "sys-mremap-moved-data",
        (tags(moved, 2), all_bytes(moved + 2 * PAGE, 2 * PAGE, 0)),
        (tags_of([0x40, 0x41]), true),
    );
    t.eq(
        "sys-mremap-moved-old",
        mapped(low, 2 * PAGE),
        Err(Errno::ENOMEM),
    );
    t.eq("sys-mremap-moved-address", moved, top_down);
    let _ = sys(Sysno::munmap, &[moved, 4 * PAGE]);
    let _ = sys(Sysno::munmap, &[A + 2 * PAGE, 2 * PAGE]);
    // MREMAP_FIXED replaces whatever is at the target.
    let src = area(A, 3, PROT_RW);
    let dst = area(B, 3, PROT_RW);
    poke(dst + PAGE, 0x77);
    let flags = MREMAP_MAYMOVE | MREMAP_FIXED;
    t.eq(
        "sys-mremap-fixed",
        mremap(src, 3 * PAGE, 3 * PAGE, flags, dst),
        Ok(dst),
    );
    t.eq(
        "sys-mremap-fixed-data",
        tags(dst, 3),
        tags_of([0x40, 0x41, 0x42]),
    );
    t.eq(
        "sys-mremap-fixed-old",
        mapped(src, 3 * PAGE),
        Err(Errno::ENOMEM),
    );
    // Moving and growing at once to a fixed address.
    let c = area(A, 1, PROT_RW);
    t.eq(
        "sys-mremap-fixed-grow",
        mremap(c, PAGE, 3 * PAGE, flags, B + 0x10_0000),
        Ok(B + 0x10_0000),
    );
    t.eq(
        "sys-mremap-fixed-grow-data",
        (
            peek(B + 0x10_0000),
            all_bytes(B + 0x10_0000 + PAGE, 2 * PAGE, 0),
        ),
        (0x40, true),
    );
    // MREMAP_DONTUNMAP leaves an empty mapping behind.
    let d = area(A, 2, PROT_RW);
    let to = mremap(d, 2 * PAGE, 2 * PAGE, MREMAP_MAYMOVE | MREMAP_DONTUNMAP, 0).unwrap_or(0);
    t.holds(
        "sys-mremap-dontunmap",
        to != 0 && to != d,
        to,
        "a new address",
    );
    t.eq(
        "sys-mremap-dontunmap-data",
        tags(to, 2),
        tags_of([0x40, 0x41]),
    );
    t.eq(
        "sys-mremap-dontunmap-old",
        (mapped(d, 2 * PAGE), all_bytes(d, 2 * PAGE, 0)),
        (Ok(0), true),
    );
    // Several mappings move together and keep their protections and the gap.
    let _ = sys(Sysno::munmap, &[A, 8 * PAGE]);
    let _ = area(A, 1, PROT_RW);
    let _ = area(A + PAGE, 1, PROT_R);
    let _ = area(A + 3 * PAGE, 1, PROT_RW);
    let to = 0x4000_0000;
    t.eq(
        "sys-mremap-multi",
        mremap(A, 4 * PAGE, 4 * PAGE, flags, to),
        Ok(to),
    );
    t.eq(
        "sys-mremap-multi-layout",
        (
            tags(to, 2),
            mapped(to + 2 * PAGE, PAGE),
            peek(to + 3 * PAGE),
            mapped(A, PAGE),
        ),
        (
            tags_of([0x40, 0x40]),
            Err(Errno::ENOMEM),
            0x40,
            Err(Errno::ENOMEM),
        ),
    );
    let probe = Probe::new();
    t.holds(
        "sys-mremap-multi-protection",
        probe.writable(to, 1) && !probe.writable(to + PAGE, 1) && probe.readable(to + PAGE, 1),
        "?",
        "rw- then r--",
    );
    t.eq(
        "sys-mremap-multi-gap",
        mremap(to - PAGE, 2 * PAGE, 2 * PAGE, flags, B),
        Err(Errno::EFAULT),
    );
    // A private file mapping moves with its pages (the file is read on demand at the new place).
    if let Ok(fd) = sys(Sysno::open, &[addr(b"/bb/hello.txt\0"), 0, 0]) {
        let m = mmap(0, PAGE, PROT_R, 0x2, fd, 0).unwrap_or(0);
        let first = peek(m);
        let target = 0x5000_0000;
        t.eq(
            "sys-mremap-file",
            mremap(m, PAGE, PAGE, flags, target),
            Ok(target),
        );
        t.eq(
            "sys-mremap-file-data",
            (first, peek(target), mapped(m, PAGE)),
            (b'h', b'h', Err(Errno::ENOMEM)),
        );
        let _ = sys(Sysno::close, &[fd]);
    } else {
        t.holds("sys-mremap-file", false, "open failed", "/bb/hello.txt");
    }
}

/// `[a, b, c, d]` of the expected tags, zero padded.
const fn tags_of<const N: usize>(list: [u8; N]) -> [u8; 4] {
    let mut out = [0u8; 4];
    let mut i = 0;
    while i < N && i < 4 {
        out[i] = list[i];
        i += 1;
    }
    out
}

pub fn run() -> bool {
    let (mut passed, mut failed) = (0u32, 0u32);
    // /dev holds only /dev/console at boot; the children read /dev/null.
    let _ = sys(
        Sysno::mknod,
        &[addr(b"/dev/null\0"), 0o20_666, (1 << 8) | 3],
    );
    let _ = sys(
        Sysno::mknod,
        &[addr(b"/dev/zero\0"), 0o20_666, (1 << 8) | 5],
    );
    let null = sys(Sysno::open, &[addr(b"/dev/null\0"), O_RDWR, 0]).unwrap_or(usize::MAX);
    // /proc for `maps` (the module has no mount point; the group makes one).
    let _ = sys(Sysno::mkdir, &[addr(b"/proc\0"), 0o555]);
    let _ = sys(
        Sysno::mount,
        &[addr(b"proc\0"), addr(b"/proc\0"), addr(b"proc\0"), 0, 0],
    );
    run_commands(&mut passed, &mut failed, null);
    layouts(&mut passed, &mut failed);
    let mut t = T::new("dynelf");
    errors(&mut t);
    mremap_checks(&mut t);
    clone_checks(&mut t);
    super::dynsys::checks(&mut t);
    let (p, f) = t.counts();
    passed += p;
    failed += f;
    emit(format_args!(
        "init: tests dynelf passed={passed} failed={failed}"
    ));
    failed == 0
}
