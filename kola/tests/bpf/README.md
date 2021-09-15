## BPF

This directory holds the BPF `kola` related tests.

* `bpf.execsnoop`: runs `execsnoop` command with `-n docker -l ps` argument, generate some noise and assert only `docker ps` are caught.
