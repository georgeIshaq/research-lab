# Lambda GPU lab connector

A small MCP server that lets Claude drive your Lambda Cloud GPU account. It runs on
Google Cloud Run (free tier), has no AI in it, and you add it to Claude as a custom
connector. Claude then gets these tools:

| Tool | What it does |
| --- | --- |
| `list_instance_types` | Types with hourly price, specs, regions with capacity, max hours within the cap |
| `estimate_cost` | Cost of a type for N hours, and whether it fits the cap |
| `launch_instance` | Launch one instance with a hard `max_hours`; refused if price × (max_hours + 10 min) > `MAX_EXPERIMENT_USD` |
| `list_instances` | Connector-launched instances: status, IP, time left, cost so far |
| `terminate_instance` | Terminate a connector-launched instance |
| `run_command` | Shell command over SSH (foreground, or detached with output to a log file) |
| `tail_log` | Last lines of a log file |
| `gpu_status` | `nvidia-smi` utilisation, memory, temperature, power and GPU processes |
| `read_file` / `write_file` | Read or write files on the instance over SFTP (5 MB per call) |
| `spend_log` | Every launch and termination with its estimated cost, plus totals |

Guard rails:

- **Only its own instances.** Every instance it launches is named `claude-lab-<label>-<deadline>`.
  It lists, SSHes into and terminates only instances whose name starts with `claude-lab-`.
  Your other Lambda instances are invisible to it. Don't give your own instances that prefix.
- **Spending cap.** `MAX_EXPERIMENT_USD` (default 500) per launch, `MAX_HOURS_LIMIT` (default 72)
  hours per launch, `MAX_CONCURRENT_INSTANCES` (default 3) at once.
- **Auto-shutdown.** Cloud Scheduler calls `/tasks/reap` every 10 minutes, which terminates any
  connector instance past its `max_hours`. The launch check already counts those 10 minutes.
- **Secrets stay in Secret Manager.** The Lambda API key, SSH private key, token signing key and
  owner passphrase are injected by Cloud Run from Secret Manager. Nothing secret is in the repo,
  logged, or returned by a tool.

## How sign-in works (and the tradeoff)

The connector is its own OAuth server, which is what Claude custom connectors support best:
when you click Connect in Claude, a page opens asking for an **owner passphrase** that only you
have. Enter it and Claude gets a 1 hour access token plus a 30 day refresh token that rotates on
every use (a replayed refresh token kills that sign-in). Sign-in only ever redirects back to
Claude's own callback (`claude.ai` / `claude.com`, or `localhost` for Claude Code), and ten wrong
passphrases lock the page for 15 minutes.

The tradeoff: Claude doesn't tell the server *which* Claude account is connecting, so what
actually limits use to you is possession of the passphrase, not your account identity. Keep the
passphrase in your password manager. To log every connected client out at once, rotate the
signing key (see "Revoke all access" below).

A plain secret token was the alternative. Claude only accepts a fixed header token for
organization Owners in a limited beta, and a token in the URL would end up in logs, so OAuth is
the better fit here.

## Setup

You need: the `gcloud` CLI logged in (`gcloud auth login`), a Google Cloud billing account (Cloud
Run's free tier still needs billing enabled; this setup stays inside the free tiers), `openssl`,
`ssh-keygen`, and a Lambda Cloud API key (Lambda dashboard → API keys → Generate).

Run every block below in one terminal session, from the `connector/` folder of this repo.

### 1. Pick names

```bash
export PROJECT_ID="claude-lab-$(openssl rand -hex 3)"   # or any unused project id
export REGION="us-central1"                             # a free-tier region
export SERVICE="lambda-lab"
```

### 2. Create the project and turn on the APIs

```bash
gcloud projects create "$PROJECT_ID" --name="Claude GPU lab"
gcloud billing accounts list
```

Copy your billing account id (looks like `0X0X0X-0X0X0X-0X0X0X`) from that list, then:

```bash
export BILLING_ACCOUNT="PASTE-IT-HERE"
gcloud billing projects link "$PROJECT_ID" --billing-account="$BILLING_ACCOUNT"
gcloud config set project "$PROJECT_ID"
gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com \
  secretmanager.googleapis.com cloudscheduler.googleapis.com storage.googleapis.com iam.googleapis.com
```

### 3. Service accounts and the state bucket

```bash
gcloud iam service-accounts create lab-connector --display-name="Lambda lab connector (runtime)"
gcloud iam service-accounts create lab-reaper --display-name="Lambda lab reaper (scheduler)"
export RUNTIME_SA="lab-connector@${PROJECT_ID}.iam.gserviceaccount.com"
export REAPER_SA="lab-reaper@${PROJECT_ID}.iam.gserviceaccount.com"

export BUCKET="${PROJECT_ID}-lab-state"
gcloud storage buckets create "gs://${BUCKET}" --location="$REGION" --uniform-bucket-level-access
gcloud storage buckets add-iam-policy-binding "gs://${BUCKET}" \
  --member="serviceAccount:${RUNTIME_SA}" --role="roles/storage.objectAdmin"
```

### 4. Secrets

The Lambda API key (typed in, so it doesn't land in your shell history):

```bash
read -rs -p "Lambda API key: " LAMBDA_KEY; echo
printf '%s' "$LAMBDA_KEY" | gcloud secrets create lambda-api-key --data-file=-
unset LAMBDA_KEY
```

The SSH key the connector uses to reach instances. The connector registers its public half
with Lambda on the first launch, as `claude-lab-connector`:

```bash
ssh-keygen -t ed25519 -N "" -C claude-lab-connector -f ./lab_key
gcloud secrets create lab-ssh-private-key --data-file=./lab_key
mkdir -p ~/.ssh && mv ./lab_key ~/.ssh/claude_lab_key && chmod 600 ~/.ssh/claude_lab_key && rm ./lab_key.pub
```

(Keeping `~/.ssh/claude_lab_key` lets you SSH into a connector instance yourself:
`ssh -i ~/.ssh/claude_lab_key ubuntu@<ip>`. Delete it if you don't want that.)

The token signing key and your owner passphrase:

```bash
openssl rand -base64 48 | tr -d '\n' | gcloud secrets create lab-oauth-signing-key --data-file=-
OWNER_PASSPHRASE="$(openssl rand -base64 24)"
printf '%s' "$OWNER_PASSPHRASE" | gcloud secrets create lab-owner-passphrase --data-file=-
echo "Owner passphrase (save this in your password manager): $OWNER_PASSPHRASE"
unset OWNER_PASSPHRASE
```

Let the service read them:

```bash
for s in lambda-api-key lab-ssh-private-key lab-oauth-signing-key lab-owner-passphrase; do
  gcloud secrets add-iam-policy-binding "$s" \
    --member="serviceAccount:${RUNTIME_SA}" --role="roles/secretmanager.secretAccessor"
done
```

### 5. Deploy

```bash
gcloud run deploy "$SERVICE" --source . --region "$REGION" \
  --service-account "$RUNTIME_SA" \
  --allow-unauthenticated \
  --min-instances 0 --max-instances 1 --memory 512Mi --timeout 3600 \
  --set-env-vars "PUBLIC_URL=https://pending.invalid,STATE_BUCKET=${BUCKET},REAPER_SERVICE_ACCOUNT=${REAPER_SA},MAX_EXPERIMENT_USD=500" \
  --set-secrets "LAMBDA_API_KEY=lambda-api-key:latest,SSH_PRIVATE_KEY=lab-ssh-private-key:latest,OAUTH_SIGNING_KEY=lab-oauth-signing-key:latest,OWNER_PASSPHRASE=lab-owner-passphrase:latest"
```

If it asks to create an Artifact Registry repository, say yes. `--allow-unauthenticated` is
needed because Claude has to reach the sign-in pages; the `/mcp` endpoint itself refuses any
request without a valid token. (`--max-instances 1` also keeps the passphrase lockout global.)

Now tell the service its own address:

```bash
export URL="$(gcloud run services describe "$SERVICE" --region "$REGION" --format='value(status.url)')"
gcloud run services update "$SERVICE" --region "$REGION" --update-env-vars "PUBLIC_URL=${URL}"
echo "Connector URL for Claude: ${URL}/mcp"
```

Check it's up (expect `{"ok":true}` and then a JSON document whose `resource` is your `/mcp` URL):

```bash
curl -s "${URL}/healthz"; echo
curl -s "${URL}/.well-known/oauth-protected-resource/mcp"; echo
```

### 6. Auto-shutdown every 10 minutes

```bash
gcloud scheduler jobs create http lab-reaper --location "$REGION" \
  --schedule "*/10 * * * *" \
  --uri "${URL}/tasks/reap" --http-method POST \
  --oidc-service-account-email "$REAPER_SA" \
  --oidc-token-audience "${URL}/tasks/reap"
gcloud scheduler jobs run lab-reaper --location "$REGION"
```

The manual run should show up as a `200` in the service logs:

```bash
gcloud run services logs read "$SERVICE" --region "$REGION" --limit 20
```

### 7. Add it to Claude

1. In Claude, open **Settings → Connectors → Add custom connector**.
2. Name: `Lambda GPU lab`. URL: the `${URL}/mcp` value printed in step 5.
3. Leave the OAuth client ID and secret under Advanced settings empty.
4. Click **Add**, then **Connect**. A "Connect Lambda GPU lab" page opens. Paste your owner
   passphrase and click **Allow**.

## Day to day

Change the cap or limits (takes effect on the new revision):

```bash
gcloud run services update "$SERVICE" --region "$REGION" --update-env-vars "MAX_EXPERIMENT_USD=300,MAX_HOURS_LIMIT=24,MAX_CONCURRENT_INSTANCES=2"
```

Other settings: `INSTANCE_PREFIX` (default `claude-lab-`), `SSH_KEY_NAME` (default
`claude-lab-connector`), `SSH_USER` (default `ubuntu`), `REAPER_INTERVAL_MINUTES` (default 10;
keep it in step with the scheduler), `ALLOW_LOOPBACK_REDIRECTS` (default `true`, set `false` if
you'll never connect from Claude Code), `LAMBDA_API_BASE` (default `https://cloud.lambda.ai/api/v1`).

Rotate the Lambda API key:

```bash
read -rs -p "New Lambda API key: " LAMBDA_KEY; echo
printf '%s' "$LAMBDA_KEY" | gcloud secrets versions add lambda-api-key --data-file=-; unset LAMBDA_KEY
gcloud run services update "$SERVICE" --region "$REGION" --update-env-vars "ROTATED_AT=$(date +%s)"
```

### Revoke all access

Every token Claude holds stops working as soon as the signing key changes. You'll need to click
Connect in Claude again afterwards.

```bash
openssl rand -base64 48 | tr -d '\n' | gcloud secrets versions add lab-oauth-signing-key --data-file=-
gcloud run services update "$SERVICE" --region "$REGION" --update-env-vars "ROTATED_AT=$(date +%s)"
```

Change the owner passphrase the same way, with `lab-owner-passphrase`.

### Where things are recorded

The bucket holds `instances/<id>.json` (what was launched, its deadline and pinned SSH host key),
`spend/<time>-<event>-<id>.json` (the spend log) and `oauth/` (used one-time codes). Costs are
list price × time since launch; Lambda's invoice is the source of truth.

### Tear it all down

Terminate any running instances first (ask Claude, or the Lambda dashboard), then:

```bash
gcloud projects delete "$PROJECT_ID"
```

and delete the `claude-lab-connector` SSH key in the Lambda dashboard.

## Development

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest
```

Tests use a fake Lambda API, an in-memory store and an in-process SSH server, so they need no
network or credentials.
