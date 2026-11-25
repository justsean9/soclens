# Microsoft Enterprise Copilot, Copilot Studio & Security Copilot Guide (KB & Install Appendix)

This guide explains how to connect **SOCLens** to **Microsoft Enterprise Copilot Chat**, **Copilot Studio custom agents**, and **Microsoft Security Copilot** — **without requiring an Entra ID App Registration** — and how to run **multiple concurrent agent chat windows** in the SOCLens TUI, store tokens safely in your PAM/Vault, and deploy completely offline.

---

## 1. Choosing the Right Provider & Lowest-Cost Option

SOCLens supports five AI Analyst providers side-by-side (and you can open separate chat windows for each at the same time):

| Provider (`--provider`) | Microsoft Surface | Cost / Licensing Notes | Entra App Reg Needed? | Best Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **`m365_copilot`** | Microsoft 365 Enterprise Copilot Chat (`graph.microsoft.com/beta/copilot/conversations`) | Uses your existing **M365 Copilot** license ($0 extra API/token spend). *Note: Free/base M365 web-only Copilot Chat does not currently expose a public REST chat API.* | **No** (Direct Bearer token or `az_cli`) | Lowest-cost direct Enterprise Copilot Chat grounded in M365 work data + web search |
| **`copilot_studio`** *(Direct-to-Engine)* | Copilot Studio published custom agents via Connection String (`/copilotstudio/.../conversations?api-version=...`) | Uses existing Copilot Studio capacity / message packs | **No** (Power Platform Bearer token or `az_cli` auto-refresh) | Native SSE streaming directly to your Copilot Studio agent using the Native/Mobile App Connection String |
| **`copilot_directline`** | Copilot Studio published custom agents (Direct Line v3 / Token Endpoint) | Uses existing Copilot Studio message packs or Pay-As-You-Go capacity | **No** (Token Endpoint URL or Direct Line Secret) | Legacy Direct Line Secret / Token Endpoint channel |
| **`security_copilot`** | Microsoft Security Copilot (`graph.microsoft.com/beta/security/securityCopilot/workspaces`) | Uses existing Security Copilot SCU capacity + `Security Copilot Contributor` RBAC | **No** (Direct Bearer token or `az_cli`) | Defender / Sentinel / Intune SOC investigations when Security Copilot is enabled |
| **`ollama`** | Local Ollama (`http://127.0.0.1:11434`) | **$0** (runs locally / air-gapped) | **No** | Sensitive IOCs, offline investigations, zero cloud cost |
| **`openai`** | OpenAI-compatible (LM Studio, vLLM, Azure AI Foundry) | Local = **$0**; Azure = per-token | Optional API key | Custom local or Azure-hosted LLMs |

---

## 2. Obtaining Tokens Without Entra ID App Registration

If you do not have permission to create an Entra ID App Registration in your workplace tenant, use one of the token-first methods below.

### Method A: Azure CLI Auto-Refresh (`az_cli`) — *Recommended for Daily Use*

Azure CLI ships with Microsoft's built-in first-party client ID, respects corporate MFA / Conditional Access, and lets SOCLens automatically refresh expired Graph tokens in the background.

1. Sign in once from your terminal (Windows PowerShell or Linux bash):
   ```bash
   az login
   ```
2. Verify you can request a Microsoft Graph token:
   ```bash
   az account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv
   ```
3. In SOCLens (**Settings → Workspace & Defaults → Microsoft Enterprise Copilot & Security Copilot**):
   - Set **MS Copilot Auth Mode** to **`Azure CLI Auto-Refresh (az account get-access-token)`** (`az_cli`).
   - Save settings (or set `SOCLENS_MS_COPILOT_AUTH_MODE=az_cli`).

### Method B: Microsoft Graph Explorer — *Fastest (Zero Installs)*

1. Open [Microsoft Graph Explorer](https://developer.microsoft.com/graph/graph-explorer) in your corporate browser and sign in with your work account.
2. In the **Modify permissions** tab, ensure your account has consented to the Copilot Chat permissions (e.g., `Sites.Read.All`, `Mail.Read`, `People.Read.All`, `Chat.Read`, `Files.Read.All`) — or for Security Copilot, `SecurityCopilotWorkspaces.ReadWrite.All`.
3. Open the **Access token** tab and click **Copy**.
4. Paste the token into SOCLens **Settings → MS Copilot / Graph Bearer Token** (or set `SOCLENS_MS_COPILOT_TOKEN`), and leave **MS Copilot Auth Mode** set to `token`.
   - *Tip:* Graph Explorer tokens typically last ~60 minutes. SOCLens inspects the JWT `exp` claim locally and tells you immediately when it is time to refresh.

### Method C: Azure PowerShell (Windows)

```powershell
Connect-AzAccount
$token = (Get-AzAccessToken -ResourceTypeName MSGraph).Token
$token | Set-Clipboard
```
Paste into SOCLens **Settings → MS Copilot / Graph Bearer Token** (or `$env:SOCLENS_MS_COPILOT_TOKEN = $token`).

### Method D: Copilot Studio Custom Agents (Direct-to-Engine Connection String or Direct Line)

#### Option D1: Direct-to-Engine Connection String (`copilot_studio`) — *Native SSE Streaming*
1. Open your published agent in **Microsoft Copilot Studio** → **Channels** → **Native App / Mobile App** and copy the **Connection String URL**:
   ```text
   https://<env>.environment.api.powerplatform.com/copilotstudio/agenticruntime/3p/dataverse-backed/authenticated/bots/<schema>/conversations?api-version=2022-03-01-preview
   ```
2. Paste that URL into SOCLens **AI Analyst → Base URL** (or **Settings → Copilot Studio Token Endpoint**, or in `ms_copilot_agents_json` as `"base_url"`).
3. Authenticate **without an Entra ID App Registration**:
   - **Easiest (Auto-Refresh):** Run `az login` and set **MS Copilot Auth Mode** to `az_cli`. SOCLens automatically requests a Power Platform token (`az account get-access-token --resource https://api.powerplatform.com`).
   - **Manual Bearer Token:** Run `az account get-access-token --resource https://api.powerplatform.com --query accessToken -o tsv` and paste into **Settings → MS Copilot / Graph Bearer Token**.
   *(Note: If you paste a `/copilotstudio/.../conversations` URL while `copilot_directline` is selected, SOCLens automatically routes it to the Direct-to-Engine `POST` + SSE transport.)*

#### Option D2: Direct Line Token Endpoint or Direct Line Secret (`copilot_directline`)
1. Copy the **Direct Line Token Endpoint** (`.../powervirtualagents/botsbyschema/<schema>/directline/token?api-version=2022-03-01-preview`) or **Settings → Security → Web channel security → Secret 1**.
2. Paste it into SOCLens **Settings → Copilot Studio Token Endpoint** or **Copilot Studio Direct Line Secret**.

---

## 3. Configuring Multiple Named Agents & Concurrent Chat Windows

### Defining Named Agent Presets

Set **MS Copilot Named Agents (JSON)** in SOCLens Settings (or `SOCLENS_MS_COPILOT_AGENTS`) to a JSON array of agents:

```json
[
  {
    "name": "Enterprise Copilot Chat",
    "provider": "m365_copilot",
    "web_grounding": true
  },
  {
    "name": "Security Copilot (SOC)",
    "provider": "security_copilot",
    "workspace": "default"
  },
  {
    "name": "SOC Triage Agent",
    "provider": "copilot_directline",
    "token_endpoint": "https://example.environment.api.powerplatform.com/powervirtualagents/botsbyschema/cr123_socTriage/directline/token?api-version=2022-03-01-preview"
  },
  {
    "name": "SPL Query Helper",
    "provider": "copilot_directline",
    "token_endpoint": "https://example.environment.api.powerplatform.com/powervirtualagents/botsbyschema/cr123_splHelper/directline/token?api-version=2022-03-01-preview"
  }
]
```

### Using Multiple Concurrent Chat Windows in the TUI

1. Open the **AI Analyst** tab (`F7`) in `soclens tui`.
2. Use the **Chat Session Bar** at the top of the pane:
   - Click **`+ New Chat`** to open a new independent chat window.
   - Switch between open chats with the session selector (`Chat 1: M365 Copilot`, `Chat 2: Security Copilot`, `Chat 3: SOC Triage Agent`, `Chat 4: Ollama`).
   - Each chat window keeps its own **provider, agent/model, server-side `conversation_id`, scrollback transcript, attached Splunk/S1/RF pivot context, and background worker** — so you can send a prompt to Security Copilot in Chat 2 while actively chatting with Enterprise Copilot Chat in Chat 1.
   - Busy background chats display a `●` indicator and notify you when their reply arrives.
   - Click **`Close Chat`** to close the active window, or **`Clear`** to reset its transcript and start a fresh server-side conversation thread.

---

## 4. Preparing & Enabling Microsoft Security Copilot

SOCLens includes a ready-to-use `security_copilot` provider targeting Microsoft Graph Beta (`workspaces/{workspaceId}/sessions` → `prompts` → `evaluations`):

1. **Tenant Prerequisites:**
   - Security Copilot provisioned with Security Compute Units (SCUs).
   - Your user account assigned at least the **Security Copilot Contributor** role.
   - Delegated Graph permission `SecurityCopilotWorkspaces.ReadWrite.All` consented on your token (via `az login` or Graph Explorer).
2. **Configuration:**
   - **Security Copilot Workspace ID:** Leave as `default` unless your organization uses a custom workspace ID.
   - **Security Copilot Poll Interval (s):** Default `2.0` seconds.
   - **MS Graph Base URL:** Default `https://graph.microsoft.com/beta` (use `https://graph.microsoft.us/beta` for GCC-High / DoD).
3. **Verify Readiness from CLI:**
   ```bash
   soclens llm status --provider security_copilot
   ```
   If SCUs or RBAC are not yet provisioned, SOCLens reports the exact HTTP 403/404 diagnostic cleanly.
4. **Run a Security Copilot Investigation Turn:**
   ```bash
   soclens llm chat --provider security_copilot --prompt "Summarize KQL hunt steps for EncodedCommand PowerShell execution" --json
   # Continue the same Security Copilot session:
   soclens llm chat --provider security_copilot --conversation-id <session_id> --prompt "Now map those to MITRE ATT&CK"
   ```

---

## 5. CLI Quick Reference

```bash
# Check connectivity
soclens llm status --provider m365_copilot
soclens llm status --provider copilot_directline
soclens llm status --provider security_copilot

# List configured named agents
soclens llm agents

# Chat with Enterprise Copilot Chat
soclens llm chat --provider m365_copilot --prompt "Summarize indicators of Living-off-the-Land binaries"

# Chat with a named Copilot Studio agent preset
soclens llm chat --agent "SOC Triage Agent" --template triage_alert --file alert.json

# Explain a Sigma rule with Enterprise Copilot
soclens llm explain-sigma --provider m365_copilot --file suspicious_ps.yml
```

---

## 6. Storing Tokens Securely (Encrypted Settings & PAM / Vault)

All Copilot secret fields (`ms_copilot_bearer_token`, `ms_copilot_token_endpoint`, `ms_copilot_directline_secret`) are:
- Encrypted at rest in SOCLens's per-user `settings.json` (never committed to Git and never included in offline deployment bundles).
- Registered as **PAM / Secret Manager managed keys**, so you can map them directly to **Akeyless**, **Bitwarden**, **HashiCorp Vault**, **1Password Connect**, or **Delinea Secret Server** via **Settings → Secret Manager (PAM / Vault)**.

---

## 7. Appendix: Online & Air-Gapped Offline Installation

SOCLens's Microsoft Copilot integration uses the existing `requests` + `ConfiguredSession` stack, so **no extra Python packages are required** beyond the standard SOCLens dependencies.

### Standard Online Install
```bash
pip install -e .
# Or with dev tools (pytest, ruff, mypy):
pip install -e ".[dev]"
```

### Air-Gapped Offline Install (Windows)
```powershell
Expand-Archive .\soclens-v2.3.2-offline-win_amd64.zip -DestinationPath .\soclens
cd .\soclens
.\install_offline.ps1 -LaunchTui
```

### Air-Gapped Offline Install (Linux)
```bash
unzip soclens-v2.3.2-offline-linux_x86_64.zip -d soclens
cd soclens
./install_offline.sh --launch-tui
```

### Rebuilding the Offline Wheelhouse (After Adding Any Future Dependencies)
Whenever new Python dependencies are added to `pyproject.toml`, rebuild and verify the offline wheelhouse on an internet-connected machine before transferring the bundle:
```bash
python scripts/build_wheelhouse.py
python scripts/build_release_bundles.py
```

---

## 8. Troubleshooting

| Symptom | Cause | Fix |
| :--- | :--- | :--- |
| `Microsoft Graph Bearer token expired ~Xm ago` or `HTTP 401` | Graph access tokens expire after ~60 minutes | Refresh from Graph Explorer / `Get-AzAccessToken`, or switch **MS Copilot Auth Mode** to `az_cli` for automatic renewal |
| `HTTP 403 Access denied` on `m365_copilot` | Missing M365 Copilot license or unconsented Graph scopes | Verify your user has an M365 Copilot license and consent scopes in Graph Explorer, or use `copilot_directline` (Copilot Studio Token Endpoint) |
| `HTTP 403` / `404` on `security_copilot` | Security Copilot SCUs not provisioned or user lacks `Security Copilot Contributor` role | Verify workspace ID (`default`) and RBAC assignment in the Security Copilot portal |
| SSL / TLS certificate error on corporate network | Corporate SSL inspection proxy | Configure **CA Bundle Path** in **Settings → Network, SSL & Proxy** (automatically inherited by all Copilot transports) |
| Government / Sovereign Cloud tenant | Commercial `graph.microsoft.com` endpoint used on GCC-High/DoD | Set **MS Graph Base URL** to `https://graph.microsoft.us/beta` (or `https://dod-graph.microsoft.us/beta`) |
