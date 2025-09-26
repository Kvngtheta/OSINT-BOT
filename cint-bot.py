# ─────────────────────────────────────────────────────────────────────────────
# File: main.py
# Description: Discord cyber-intel bot that ingests a source channel of news,
#              summarizes & cross-references intel, and posts actionable items
#              to a destination channel. Includes slash commands for on-demand
#              analysis. Secure-by-default: no secrets in code, strict timeouts,
#              input validation, least privilege, and careful error handling.
# ─────────────────────────────────────────────────────────────────────────────

import os
import re
import json
import asyncio
import logging
import sqlite3
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Tuple, Dict, Any

import aiohttp
from aiohttp import ClientSession
import discord
from discord import app_commands
from discord.ext import commands, tasks

# OpenAI Python SDK v1.x
from openai import OpenAI

# ─────────────────────────────────────────────────────────────────────────────
# Configuration (via environment variables) — NO HARDCODED SECRETS
# ─────────────────────────────────────────────────────────────────────────────
DISCORD_BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# Numeric IDs for channels (optional at startup, can be set via command)
NEWS_CHANNEL_ID = os.getenv("NEWS_CHANNEL_ID")
INTEL_CHANNEL_ID = os.getenv("INTEL_CHANNEL_ID")

# Comma-separated allowlist of Discord role IDs that can use admin commands
ADMIN_ROLE_IDS = [rid.strip() for rid in os.getenv("ADMIN_ROLE_IDS", "").split(",") if rid.strip()]

# Cross-ref OSINT/RSS feeds (override via env; defaults provided)
DEFAULT_FEEDS = [
    # CISA, NCSC, MSRC, etc. — publicly accessible advisory/news feeds
    "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml",
    "https://msrc-blog.microsoft.com/feed/",
    "https://www.bleepingcomputer.com/feed/",
    "https://krebsonsecurity.com/feed/",
]
FEEDS = [u.strip() for u in os.getenv("INTEL_FEEDS", ",".join(DEFAULT_FEEDS)).split(",") if u.strip()]

# Rate limiting / timeouts / sizes
HTTP_TIMEOUT_SECS = int(os.getenv("HTTP_TIMEOUT_SECS", "20"))
CONCURRENT_HTTP = int(os.getenv("CONCURRENT_HTTP", "5"))
MAX_ARTICLE_BYTES = int(os.getenv("MAX_ARTICLE_BYTES", str(800_000)))  # ~0.8 MB cap
POLL_INTERVAL_SECS = int(os.getenv("POLL_INTERVAL_SECS", "90"))
MAX_MESSAGES_PER_POLL = int(os.getenv("MAX_MESSAGES_PER_POLL", "25"))

# OpenAI model & safety
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
OPENAI_MAX_TOKENS = int(os.getenv("OPENAI_MAX_TOKENS", "700"))
OPENAI_TEMPERATURE = float(os.getenv("OPENAI_TEMPERATURE", "0.2"))

# Database path
DB_PATH = os.getenv("DB_PATH", "bot_state.sqlite3")

# Logging
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("cyber-intel-bot")

# ─────────────────────────────────────────────────────────────────────────────
# Minimal HTML cleaning (avoid heavy deps). We only need simple text extraction.
# ─────────────────────────────────────────────────────────────────────────────
TAG_RE = re.compile(r"<[^>]+>")
SCRIPT_STYLE_RE = re.compile(r"<(script|style)[\s\S]*?>[\s\S]*?</(script|style)>", re.IGNORECASE)
WHITESPACE_RE = re.compile(r"\s+")
URL_RE = re.compile(r"https?://[^\s>]+", re.IGNORECASE)


def strip_html(html: str) -> str:
    if not html:
        return ""
    html = SCRIPT_STYLE_RE.sub(" ", html)
    html = TAG_RE.sub(" ", html)
    html = WHITESPACE_RE.sub(" ", html)
    return html.strip()


# ─────────────────────────────────────────────────────────────────────────────
# SQLite state: last processed message per channel, and seen URLs
# ─────────────────────────────────────────────────────────────────────────────

def init_db(path: str = DB_PATH):
    with sqlite3.connect(path) as conn:
        c = conn.cursor()
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS channel_state (
                channel_id TEXT PRIMARY KEY,
                last_msg_id TEXT,
                updated_at TEXT
            )
            """
        )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS seen_urls (
                url TEXT PRIMARY KEY,
                first_seen TEXT
            )
            """
        )
        conn.commit()


def get_last_msg_id(channel_id: int) -> Optional[int]:
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT last_msg_id FROM channel_state WHERE channel_id = ?", (str(channel_id),))
        row = c.fetchone()
        return int(row[0]) if row and row[0] is not None else None


def set_last_msg_id(channel_id: int, msg_id: int):
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute(
            """
            INSERT INTO channel_state(channel_id, last_msg_id, updated_at)
            VALUES(?, ?, ?)
            ON CONFLICT(channel_id) DO UPDATE SET last_msg_id=excluded.last_msg_id, updated_at=excluded.updated_at
            """,
            (str(channel_id), str(msg_id), datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()


def mark_url_seen(url: str) -> bool:
    # Returns True if newly inserted
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        try:
            c.execute("INSERT INTO seen_urls(url, first_seen) VALUES(?, ?)", (url, datetime.now(timezone.utc).isoformat()))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False


# ─────────────────────────────────────────────────────────────────────────────
# URL extraction and fetching
# ─────────────────────────────────────────────────────────────────────────────

def extract_urls(text: str) -> List[str]:
    if not text:
        return []
    urls = URL_RE.findall(text)
    # Basic sanitize: strip trailing punctuation
    clean = []
    for u in urls:
        clean.append(u.rstrip("),.>]"))
    return list(dict.fromkeys(clean))  # dedupe preserving order


async def fetch_text(session: ClientSession, url: str, max_bytes: int = MAX_ARTICLE_BYTES) -> Optional[str]:
    # Basic domain allowlist/denylist could be added here if desired.
    try:
        async with session.get(url, timeout=HTTP_TIMEOUT_SECS, allow_redirects=True, headers={
            "User-Agent": "CyberIntelBot/1.0 (+security research; contact admin)"
        }) as resp:
            if resp.status != 200:
                logger.warning(f"Fetch {url} -> HTTP {resp.status}")
                return None
            total = 0
            chunks = []
            async for chunk in resp.content.iter_chunked(4096):
                total += len(chunk)
                if total > max_bytes:
                    logger.warning(f"Fetch {url} exceeded max size {max_bytes}")
                    break
                chunks.append(chunk)
            if not chunks:
                return None
            # Try to decode as text
            ct = resp.headers.get("Content-Type", "")
            charset = None
            if "charset=" in ct:
                charset = ct.split("charset=")[-1].strip()
            try:
                data = b"".join(chunks).decode(charset or "utf-8", errors="replace")
            except Exception:
                data = b"".join(chunks).decode("utf-8", errors="replace")
            return data
    except asyncio.TimeoutError:
        logger.warning(f"Timeout fetching {url}")
        return None
    except Exception as e:
        logger.exception(f"Error fetching {url}: {e}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# OpenAI summarization / actionable intel
# ─────────────────────────────────────────────────────────────────────────────

def get_openai_client() -> OpenAI:
    if not OPENAI_API_KEY:
        raise RuntimeError("OPENAI_API_KEY missing")
    return OpenAI(api_key=OPENAI_API_KEY)


async def summarize_actionable(article_text: str, source_url: str, client: OpenAI) -> str:
    # Truncate overly long text to control tokens
    text = article_text
    if len(text) > 120_000:
        text = text[:120_000]

    system = (
        "You are a cybersecurity threat intelligence analyst. Produce concise,"
        " high-signal actionable intelligence for defenders at a bank. Use bullet"
        " points. Include: TL;DR (1-2 lines), Who/What/How (TTPs, CVEs, IOCs),"
        " Impact/Risk scoring (High/Med/Low with rationale), Detection ideas (KQL/ Splunk-like hints),"
        " Mitigations/patch guidance, and References (include the source URL)."
    )
    user = (
        f"Source: {source_url}\n\n"
        f"Content (plain text):\n{text}\n\n"
        "Return JSON with keys: tldr, who_what_how, impact, detection_ideas, mitigations, references."
    )

    # Use responses.create with JSON schema-like instruction
    resp = client.chat.completions.create(
        model=OPENAI_MODEL,
        temperature=OPENAI_TEMPERATURE,
        max_tokens=OPENAI_MAX_TOKENS,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        response_format={"type": "json_object"},
    )
    return resp.choices[0].message.content


# ─────────────────────────────────────────────────────────────────────────────
# Cross-reference with intel feeds (simple RSS text matching)
# ─────────────────────────────────────────────────────────────────────────────
async def fetch_feed_entries(session: ClientSession, feed_url: str, limit: int = 15) -> List[Dict[str, Any]]:
    try:
        async with session.get(feed_url, timeout=HTTP_TIMEOUT_SECS, headers={
            "User-Agent": "CyberIntelBot/1.0"
        }) as resp:
            if resp.status != 200:
                return []
            text = await resp.text()
    except Exception:
        return []

    # Minimal RSS/Atom parsing without heavy deps
    # We'll regex out <item> or <entry> titles+links+descriptions
    items: List[Dict[str, Any]] = []
    try:
        # Try RSS <item>
        for m in re.finditer(r"<item>(.*?)</item>", text, re.IGNORECASE | re.DOTALL):
            block = m.group(1)
            title = re.search(r"<title>(.*?)</title>", block, re.IGNORECASE | re.DOTALL)
            link = re.search(r"<link>(.*?)</link>", block, re.IGNORECASE | re.DOTALL)
            desc = re.search(r"<description>(.*?)</description>", block, re.IGNORECASE | re.DOTALL)
            items.append({
                "title": strip_html(title.group(1)) if title else "",
                "link": strip_html(link.group(1)) if link else "",
                "summary": strip_html(desc.group(1)) if desc else "",
            })
        # Fallback Atom <entry>
        if not items:
            for m in re.finditer(r"<entry>(.*?)</entry>", text, re.IGNORECASE | re.DOTALL):
                block = m.group(1)
                title = re.search(r"<title>(.*?)</title>", block, re.IGNORECASE | re.DOTALL)
                link = re.search(r"<link[^>]*href=\"(.*?)\"", block, re.IGNORECASE | re.DOTALL)
                summary = re.search(r"<summary>(.*?)</summary>", block, re.IGNORECASE | re.DOTALL)
                items.append({
                    "title": strip_html(title.group(1)) if title else "",
                    "link": link.group(1) if link else "",
                    "summary": strip_html(summary.group(1)) if summary else "",
                })
    except Exception:
        return []

    return items[:limit]


async def cross_reference(session: ClientSession, indicators: List[str]) -> List[Dict[str, Any]]:
    matches: List[Dict[str, Any]] = []
    indicators_lower = [i.lower() for i in indicators if i]

    for feed in FEEDS:
        entries = await fetch_feed_entries(session, feed)
        for e in entries:
            hay = f"{e.get('title','')}\n{e.get('summary','')}".lower()
            if any(ind in hay for ind in indicators_lower):
                matches.append({"feed": feed, **e})
    return matches[:20]


# ─────────────────────────────────────────────────────────────────────────────
# Discord Bot
# ─────────────────────────────────────────────────────────────────────────────
intents = discord.Intents.default()
intents.message_content = True  # must be enabled in the Discord developer portal
intents.guilds = True
intents.members = False

bot = commands.Bot(command_prefix="!", intents=intents)
client_openai: Optional[OpenAI] = None
http_semaphore = asyncio.Semaphore(CONCURRENT_HTTP)


def is_admin(interaction: discord.Interaction) -> bool:
    if not ADMIN_ROLE_IDS:
        return interaction.user.guild_permissions.administrator  # fallback
    role_ids = {str(r.id) for r in getattr(interaction.user, 'roles', [])}
    return any(rid in role_ids for rid in ADMIN_ROLE_IDS)


async def post_actionable(channel: discord.abc.Messageable, payload: Dict[str, Any]):
    # Limit field sizes and format as an embed
    embed = discord.Embed(
        title="Actionable Intelligence",
        description=payload.get("tldr", "No TL;DR"),
        color=discord.Color.blue(),
        timestamp=datetime.now(timezone.utc),
    )
    def add_field(name: str, key: str):
        val = payload.get(key)
        if not val:
            return
        if isinstance(val, list):
            val = "\n".join(f"• {v}" for v in val[:10])
        elif isinstance(val, str) and len(val) > 1000:
            val = val[:1000] + "…"
        embed.add_field(name=name, value=val, inline=False)

    add_field("Who/What/How", "who_what_how")
    add_field("Impact / Risk", "impact")
    add_field("Detection Ideas", "detection_ideas")
    add_field("Mitigations", "mitigations")

    refs = payload.get("references")
    if refs:
        if isinstance(refs, list):
            refs_str = "\n".join(refs[:10])
        else:
            refs_str = str(refs)
        if len(refs_str) > 1000:
            refs_str = refs_str[:1000] + "…"
        embed.add_field(name="References", value=refs_str, inline=False)

    await channel.send(embed=embed)


@bot.event
async def on_ready():
    global client_openai
    logger.info(f"Logged in as {bot.user} (ID: {bot.user.id})")
    try:
        await bot.tree.sync()
        logger.info("Slash commands synced.")
    except Exception as e:
        logger.exception(f"Slash sync failed: {e}")

    init_db()

    if OPENAI_API_KEY:
        try:
            client_openai = get_openai_client()
            logger.info("OpenAI client initialized.")
        except Exception as e:
            logger.exception(f"OpenAI init error: {e}")

    # Start background poller only if channels are set
    try:
        if NEWS_CHANNEL_ID and INTEL_CHANNEL_ID:
            news_loop.change_interval(seconds=POLL_INTERVAL_SECS)
            news_loop.start()
            logger.info("Background news loop started.")
        else:
            logger.warning("NEWS_CHANNEL_ID or INTEL_CHANNEL_ID not set; background loop not started.")
    except Exception as e:
        logger.exception(f"Error starting loop: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# Background task: read new messages in news channel -> summarize -> post intel
# ─────────────────────────────────────────────────────────────────────────────
@tasks.loop(seconds=120)
async def news_loop():
    if not (NEWS_CHANNEL_ID and INTEL_CHANNEL_ID and client_openai):
        return
    guilds = bot.guilds
    if not guilds:
        return

    try:
        news_channel = bot.get_channel(int(NEWS_CHANNEL_ID))
        intel_channel = bot.get_channel(int(INTEL_CHANNEL_ID))
        if not (news_channel and intel_channel):
            return

        last_id = get_last_msg_id(news_channel.id)
        after = discord.Object(id=last_id) if last_id else None

        fetched = []
        async for msg in news_channel.history(limit=MAX_MESSAGES_PER_POLL, after=after, oldest_first=True):
            fetched.append(msg)

        if not fetched:
            return

        async with aiohttp.ClientSession() as session:
            for msg in fetched:
                try:
                    urls = extract_urls(msg.content)
                    if not urls:
                        continue
                    for url in urls[:3]:  # limit per message
                        # dedupe by URL
                        if not mark_url_seen(url):
                            continue
                        async with http_semaphore:
                            html = await fetch_text(session, url)
                        if not html:
                            continue
                        text = strip_html(html)
                        if not text or len(text) < 300:
                            continue

                        # Summarize
                        summary_json = await asyncio.to_thread(summarize_actionable, text, url, client_openai)
                        payload = json.loads(summary_json)

                        # Cross-ref basic keywords (vendor names, CVE IDs)
                        iocs = re.findall(r"CVE-\d{4}-\d{4,7}", text)
                        vendors = []
                        for pat in [r"Microsoft", r"Cisco", r"Fortinet", r"Palo Alto", r"Ivanti", r"Atlassian", r"VMware", r"Progress", r"Citrix"]:
                            if re.search(pat, text, re.IGNORECASE):
                                vendors.append(pat)
                        indicators = list(set(iocs + vendors))[:10]
                        xrefs = await cross_reference(session, indicators) if indicators else []
                        if xrefs:
                            payload.setdefault("references", [])
                            if isinstance(payload["references"], list):
                                payload["references"].extend([x.get("link") for x in xrefs if x.get("link")])
                            else:
                                payload["references"] = [payload["references"]] + [x.get("link") for x in xrefs if x.get("link")]

                        await post_actionable(intel_channel, payload)
                finally:
                    set_last_msg_id(news_channel.id, msg.id)
    except Exception as e:
        logger.exception(f"news_loop error: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# Slash Commands
# ─────────────────────────────────────────────────────────────────────────────
@bot.tree.command(name="intel_help", description="Show bot commands and usage.")
async def intel_help(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    embed = discord.Embed(title="Cyber Intel Bot — Commands", color=discord.Color.green())
    embed.add_field(name="/triage url:<link>", value="Summarize a single article and produce actionable intel.", inline=False)
    embed.add_field(name="/intel query:<text>", value="Query OSINT feeds and summarize current intel for keywords (e.g., CVE, vendor, malware).", inline=False)
    embed.add_field(name="/summarize_recent count:<1-10>", value="Summarize the last N messages with links from the news channel.", inline=False)
    embed.add_field(name="/set_channels news:<#channel> intel:<#channel>", value="Admin only. Configure ingestion and destination channels.", inline=False)
    await interaction.followup.send(embed=embed, ephemeral=True)


@bot.tree.command(name="set_channels", description="Admin: set news & intel channels.")
@app_commands.describe(news="Source channel with news posts", intel="Destination channel for actionable intel")
async def set_channels(interaction: discord.Interaction, news: discord.TextChannel, intel: discord.TextChannel):
    if not is_admin(interaction):
        await interaction.response.send_message("Insufficient permissions.", ephemeral=True)
        return
    global NEWS_CHANNEL_ID, INTEL_CHANNEL_ID
    NEWS_CHANNEL_ID = str(news.id)
    INTEL_CHANNEL_ID = str(intel.id)
    await interaction.response.send_message(f"Channels set. News: {news.mention}, Intel: {intel.mention}", ephemeral=True)


@bot.tree.command(name="triage", description="Summarize a single URL for actionable intel.")
@app_commands.describe(url="Article or advisory URL")
async def triage(interaction: discord.Interaction, url: str):
    await interaction.response.defer(thinking=True, ephemeral=True)
    if not client_openai:
        await interaction.followup.send("OpenAI client not configured.", ephemeral=True)
        return

    # Basic URL validation
    if not re.match(r"^https?://", url, re.IGNORECASE):
        await interaction.followup.send("Invalid URL.", ephemeral=True)
        return

    async with aiohttp.ClientSession() as session:
        async with http_semaphore:
            html = await fetch_text(session, url)
        if not html:
            await interaction.followup.send("Could not fetch URL.", ephemeral=True)
            return
        text = strip_html(html)
        summary_json = await asyncio.to_thread(summarize_actionable, text, url, client_openai)
        payload = json.loads(summary_json)

    # Post to current channel for visibility
    await post_actionable(interaction.channel, payload)
    await interaction.followup.send("Posted actionable intel.", ephemeral=True)


@bot.tree.command(name="intel", description="Query feeds and summarize relevant intel.")
@app_commands.describe(query="Keywords: CVE-YYYY-NNNN, vendor, malware, etc.")
async def intel(interaction: discord.Interaction, query: str):
    await interaction.response.defer(thinking=True)
    q = query.strip()
    if not q or len(q) < 2:
        await interaction.followup.send("Provide a useful keyword.", ephemeral=True)
        return

    indicators = [q]
    async with aiohttp.ClientSession() as session:
        xrefs = await cross_reference(session, indicators)

    # Summarize the matches with OpenAI for an at-a-glance action plan
    text_blurb = "\n\n".join([f"- {e['title']}\n{e['summary']}\n{e['link']}" for e in xrefs[:8]]) or "No matches found."

    if client_openai and text_blurb != "No matches found.":
        system = (
            "You are a cyber threat intel analyst. Summarize the items into a single"
            " actionable brief with TL;DR, key risks, and next steps for defenders."
        )
        user = text_blurb
        resp = client_openai.chat.completions.create(
            model=OPENAI_MODEL,
            temperature=OPENAI_TEMPERATURE,
            max_tokens=OPENAI_MAX_TOKENS,
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
        )
        summary = resp.choices[0].message.content
    else:
        summary = text_blurb

    embed = discord.Embed(title=f"Intel query: {q}", description=summary[:4000], color=discord.Color.orange())
    await interaction.followup.send(embed=embed)


@bot.tree.command(name="summarize_recent", description="Summarize last N news posts (with URLs).")
@app_commands.describe(count="Number of messages (1-10)")
async def summarize_recent(interaction: discord.Interaction, count: app_commands.Range[int, 1, 10] = 5):
    await interaction.response.defer(thinking=True)

    if not NEWS_CHANNEL_ID:
        await interaction.followup.send("NEWS_CHANNEL_ID not set.", ephemeral=True)
        return

    news_channel = bot.get_channel(int(NEWS_CHANNEL_ID))
    if not news_channel:
        await interaction.followup.send("News channel not found.", ephemeral=True)
        return

    messages = []
    async for msg in news_channel.history(limit=count, oldest_first=False):
        if extract_urls(msg.content):
            messages.append(msg)
        if len(messages) >= count:
            break

    if not messages:
        await interaction.followup.send("No recent messages with URLs.", ephemeral=True)
        return

    summaries = []
    async with aiohttp.ClientSession() as session:
        for msg in messages:
            for url in extract_urls(msg.content)[:2]:
                async with http_semaphore:
                    html = await fetch_text(session, url)
                if not html:
                    continue
                text = strip_html(html)
                if client_openai:
                    sj = await asyncio.to_thread(summarize_actionable, text, url, client_openai)
                    payload = json.loads(sj)
                    summaries.append(f"**{payload.get('tldr','(no tldr)')}**\n{payload.get('references', url)}")
                else:
                    summaries.append(f"{url}\n{text[:400]}…")

    description = "\n\n".join(summaries)[:3900]
    embed = discord.Embed(title="Recent Intel Summaries", description=description, color=discord.Color.blurple())
    await interaction.followup.send(embed=embed)


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if not DISCORD_BOT_TOKEN:
        raise SystemExit("DISCORD_BOT_TOKEN not set")
    bot.run(DISCORD_BOT_TOKEN, log_handler=None)
