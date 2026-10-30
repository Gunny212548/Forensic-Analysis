# Gotcha #80

**80. The attack path goes to the computer, not the account; an address is its host when Windows says so**

2026-10-30, the user's request after a mockup chain (brute force from the internet onto RDS01, then
RDP to FS01 and PsExec to SQL01 from it): the graph showed `198.51.100.66 -> adm.hd <- 10.20.0.40`
and a lone `10.20.0.40 -> 10.20.0.30`. The pivot was there, but nobody could read it as one.

Why: `db.build_graph` took an edge's target as `coalesce(dstip, username)`. A Windows logon has no
destination address - the target is the Computer that logged the event (`raw_events.hostname`) - so
every logon pointed at the account. And a host appears twice, as its name where it was reached and
as its address where it acts.

Now:

1. **Target = `coalesce(dstip, hostname, username)`.** The account rides on the edge (`accounts`, the
   ten with most events, and `account_count`; "· as adm.hd +4 accounts" at the end of the label). Only
   a row with neither address nor computer - an Entra sign-in - still points at the account. The
   account is counted once whether Sysmon wrote `DOMAIN\user`, a 4769 `user@REALM` or the Security
   log the bare name.
2. **An address is drawn as its host** (`db._host_addresses`) when the case's Windows events tie it to
   one computer, and no other: the computer's own Sysmon 3 (SourceIp when `Initiated` is true,
   DestinationIp when not), or the computer's own account `NAME$` signing in (4624) or getting a TGT
   (4768 status 0x0) from it - Windows computers do so every day from boot - when a computer of that
   name logged events in the case. Loopback and `-` never count; an address two hosts claimed (DHCP)
   stays an address. The host node's `about` lists its addresses.
3. A loopback source (`127.0.0.1 -> ry-pc014`, a console logon) stays an address on purpose: mapping
   it to the host makes the edge a self-loop, and the finding would vanish from the graph.

Measured: the mockup reads `198.51.100.66 -> rds01 -> fs01 / sql01`; Mekong's W7 / W8 run from
`ws023` to `rds01` / `sql01` (`tests/check_windows_rules.py`); Kinnaree's sprayer is
`web01 -> dc1` and `web01 -> hq-pc0nn`; the Check Point cases on 8091 kept every edge. The graph is
not in the narrative's prompt (only attached to it), so `bench_llm` is unaffected.
