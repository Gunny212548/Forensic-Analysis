# Gotcha #4

**4. Don't conflate a connection's *source* port with a *destination* port.**
In `Connection from 1.2.3.4 port 53544` that's the client's ephemeral source
port. Feeding it to a port-scan rule (which counts distinct *destination*
ports) false-positives on any host that merely reconnects a lot. `decode.py`
deliberately does not set `dstport` from SSH regex captures.
