# CINT-BOT

# Discord Cyber-Intel Bot (Secure Template)

This bot ingests a news channel, summarizes articles with OpenAI, cross-references public intel feeds, and posts **actionable intelligence** into another channel. It also supports slash commands for ad‑hoc queries.

## Features
- **Secure by default**: no hardcoded secrets, strict timeouts, input validation, least privilege.
- **Background ingestion**: polls a source channel, extracts URLs, fetches content, summarizes, cross‑refs feeds, posts embeds.
- **Slash commands**:
  - `/triage url:<link>` – summarize an article into an actionable brief.
  - `/intel query:<text>` – query public feeds (CVE/vendor/malware) and get a concise action plan.
  - `/summarize_recent count:<1-10>` – summarize the last N posts with links.
  - `/set_channels news:<#> intel:<#>` – admin‑only configuration.

## Setup
1. **Create a Discord application & bot** at https://discord.com/developers
   - Enable **MESSAGE CONTENT INTENT**.
   - Invite the bot with permissions to read the news channel and write to the intel channel.
2. **Clone & configure**
   ```bash
   python -m venv .venv && source .venv/bin/activate
   pip install -r requirements.txt
   cp .env.example .env
   # edit .env with your tokens and channel IDs
   ```
3. **Run**
   ```bash
   export $(grep -v '^#' .env | xargs -d'\n')
   python main.py
   ```
