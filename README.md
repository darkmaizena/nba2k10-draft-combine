# NBA 2K10 Draft Combine Server

A reimplementation of the auth/backend server for **NBA 2K10 Draft Combine** (Claude did most of the heavy lifting here)
(PS3, `NPUB30129`). The original service (`nba2k10.ps3.2ksports.com`) is
long dead, this let's the game communicate to your own machine to unlock the following trophy:

> **2K10: Let's Do This**
>
> Upload your player when the Draft Combine is over

I'd recommend backing up the save before trying to upload, otherwise if anything goes wrong you might have to replay all 6 games from a fresh save.

## Running

1. Install uv: https://docs.astral.sh/uv/getting-started/installation/
2. Download the project.
3. From the project folder:

```bash
uv sync
sudo uv run server.py    # port 1004 needs root
```

## DNS Redirection

You must redirect `nba2k10.ps3.2ksports.com` to your machine. Example using
NextDNS (Windows): https://gist.github.com/darkmaizena/0a89ab083c18528274982a23b2bc8d1d
