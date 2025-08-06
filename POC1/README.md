# POC1 – knockd demonstration

This miniature project shows how a server can hide an SSH service behind a
port‑knocking door. A three‑step sequence (8881, 7777, 9991) briefly opens
port **2222**, letting the user try an SSH connection before the door shuts
again thirty seconds later.

```
client -> knocks -> server -> port open -> SSH
```

## Components

- **setup_knockd.sh** – configures the server, writes `/etc/knockd.conf`, sets
  up iptables and restarts the daemon.
- **knock_client.py** – sends the knock sequence, waits, checks the port and can
  optionally close it again.

Both scripts are heavily commented so they can be dropped straight into a lab
report or exam presentation.

## Quick start

1. On the server, run:
   ```bash
   sudo ./setup_knockd.sh
   ```
2. From a client machine:
   ```bash
   python3 knock_client.py --host <SERVER_IP> --port 2222 --close
   ```
   The `--close` flag sends the reverse sequence after testing.

The client logs its actions in `knockd_demo.log` and prints a minimalist
"hacker style" output to the terminal.

## Limitations

- Intended for IPv4 networks and ephemeral lab setups.
- Uses simple TCP connection attempts; no packet crafting or authentication.
- Adjust the iptables commands if another firewall is in use.

Enjoy exploring the basics of port‑knocking!
