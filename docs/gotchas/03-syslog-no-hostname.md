# Gotcha #3

**3. Log lines without a hostname field break a naive syslog decoder.**
Standard syslog is `TIMESTAMP HOSTNAME PROGRAM[PID]: MESSAGE`; VMware ESXi
omits the hostname. A single greedy regex misparses the program as a
hostname and no program-specific decoder ever matches.
`decode._split_host_prog()` checks token-by-token instead.
