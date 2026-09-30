# Slack Channel Migration Service

A web application that allows Slack users to export their active public and private channel memberships into a tamper-proof JSON file and import them back to rejoin public channels or auto-invite via a Bot into private channels.

---

## Required Slack OAuth Scopes

Configure these scopes at [api.slack.com/apps](https://api.slack.com/apps) under **OAuth & Permissions**:

### 1. User Token Scopes (`xoxp-...`)
* `channels:read` — View public channels the user belongs to.
* `groups:read` — View private channels the user belongs to.
* `channels:join` — Join public channels in the workspace on behalf of the user.

### 2. Bot Token Scopes (`xoxb-...`)
* `channels:read` — Discover public channels in the workspace.
* `groups:read` — View private channels where the bot is a member.
* `channels:manage` — Invite users to public and private channels (`conversations.invite`).

---

## Features

1. **HMAC Signature Validation:** Export files are signed with HMAC SHA-256. Any modification to channel names or states will invalidate the signature and prevent unauthorized channel access during import.
2. **IP Whitelisting Middleware:** Restricts access to specified IP addresses using Express reverse-proxy middleware.
3. **Cross-Workspace & Reactivation Support:** Uses channel names to match target workspace channels dynamically.

---

## Local Development Setup

1. **Clone project and install dependencies:**
   ```bash
   npm install