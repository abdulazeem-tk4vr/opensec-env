# RunPod Ollama (HTTP proxy) for OpenSec eval

Use a GPU RunPod pod for LLM inference while running OpenSec eval on your local machine. You only need to set **`OLLAMA_BASE_URL`** and **`OLLAMA_MODEL`** in `.env`.

## RunPod pod setup

1. Create a pod with an **NVIDIA GPU** (8 GB VRAM minimum; 16 GB recommended).
2. Use an image or template with **Ollama** installed, or install Ollama on the pod.
3. Start Ollama listening on all interfaces:
   ```bash
   OLLAMA_HOST=0.0.0.0:11434 ollama serve
   ```
4. Pull the model you want to evaluate (must match `OLLAMA_MODEL` in `.env`):
   ```bash
   ollama pull llama3.2:3b
   ```
5. In RunPod, enable **HTTP proxy** (or “Connect”) for port **11434** and copy the public proxy URL (e.g. `https://xxxxx-xxxxx.proxy.runpod.net`).

## Local `.env` configuration

In the repo root (`opensec-env/.env`):

```env
OLLAMA_BASE_URL=https://your-id.proxy.runpod.net
OLLAMA_MODEL=llama3.2:3b
```

Use the proxy URL **without** a trailing path. Do not append `/v1` or `/api`.

Copy from the template:

```bash
cp .env.example .env
# edit OLLAMA_BASE_URL and OLLAMA_MODEL
```

## Run eval

**Bash:**

```bash
pip install -e .
python scripts/eval.py --ollama --limit 1
```

**PowerShell:**

```powershell
pip install -e .
python scripts/eval.py --ollama --limit 1
```

Or use the helper scripts:

```bash
./scripts/run_ollama_eval.sh --limit 1
```

```powershell
.\scripts\run_ollama_eval.ps1 -Limit 1
```

The eval script will:

- Load `.env` automatically
- Preflight-check `GET $OLLAMA_BASE_URL/api/tags` and confirm `OLLAMA_MODEL` is present
- Run the defender agent against OpenSec seeds via Ollama’s OpenAI-compatible API
- Write results to `outputs/ollama_eval.jsonl`

Full eval (40 standard-tier episodes):

```bash
python scripts/eval.py --ollama --tier standard --limit 40
python scripts/summarize.py outputs/ollama_eval.jsonl
```

## Verify Ollama directly

From your host:

```bash
curl -s "${OLLAMA_BASE_URL}/api/tags"
```

Skip the preflight check if you already verified connectivity:

```bash
python scripts/eval.py --ollama --skip-preflight --limit 1
```

## Local Ollama instead

If Ollama runs on your machine:

```env
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.2:3b
```

Then run the same `--ollama` command.

## Attacker policy

By default, eval uses a **mock attacker** (no extra API calls). To drive the live attacker from the same Ollama server, add to `.env`:

```env
OPENSEC_ATTACKER_SGLANG=1
SGLANG_BASE_URL=http://localhost:11434/v1
OPENSEC_ATTACKER_MODEL=llama3.2:3b
```

For remote RunPod, use your proxy URL with `/v1`:

```env
SGLANG_BASE_URL=https://your-id.proxy.runpod.net/v1
```

## Troubleshooting

| Issue | What to check |
|--------|----------------|
| Preflight fails | Pod running, proxy enabled on 11434, URL has no extra path |
| Model not found | `ollama pull` on the pod for `OLLAMA_MODEL` |
| Slow first step | Cold start on remote GPU; normal for first inference |
| Bad JSON actions | Smaller models may fail to emit valid defender JSON; try a larger model |
| SSH tunnel (optional) | Forward port 11434 and set `OLLAMA_BASE_URL=http://localhost:11434` |

## SSH tunnel (optional)

If you prefer not to use the public HTTP proxy, forward port 11434 over SSH and set:

```env
OLLAMA_BASE_URL=http://localhost:11434
```
