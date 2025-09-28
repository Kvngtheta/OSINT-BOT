# OSINT-BOT

# Discord Cyber-Intel Bot (V1)

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
   OR
   set -a; source .env; set +a
   python main.py
   ```

   ## Docker (optional)
```bash
docker build -t osint-bot:<tag> .

# You can also pull it from dockerhub; be sure to pull the latest version
sudo docker pull no0backsappi3/osint-bot:v1.0
# supply secrets at runtime; mount state volume
docker run -d --rm \
  -e DISCORD_BOT_TOKEN=... \
  -e OPENAI_API_KEY=... \
  -e NEWS_CHANNEL_ID=... \
  -e INTEL_CHANNEL_ID=... \
  -v $(pwd)/state:/state \
  docker.io/no0backsappi3/osint-bot:v1.0
```
##What's New?
- Integrated google feeds: This is will be a backup if your main feeds cannot find useful information

## Security Notes
- **Never commit** `.env` or secrets.
- Scoped tokens: restrict Discord bot permissions to only required channels.
- Input validation: the bot only fetches `http(s)` URLs; timeouts & size caps applied.
- Rate limits: concurrent HTTP semaphore to avoid abuse; add per‑user command cooldowns if needed.
- Logging: default INFO; avoid logging secrets or full article bodies.
- Update dependency pins regularly and enable Dependabot/Snyk where possible.

## Extending Cross‑Reference
Replace or extend `INTEL_FEEDS` with your organization’s paid intel feeds (via gateway API) and update `cross_reference()` to use authenticated requests.

## Troubleshooting
- If slash commands don’t appear, ensure the bot has `applications.commands` scope and re‑invite; wait a minute for global sync or use guild‑specific sync in code if needed.
- If background loop doesn’t start, ensure `NEWS_CHANNEL_ID` and `INTEL_CHANNEL_ID` are set.

## Disclaimer
This is a template. Review and adapt it to your organization’s policies, logging, and compliance requirements.
