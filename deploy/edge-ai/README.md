# HELIOS AI box (on-premises model server)

For a client whose rulebook says AI may only run on-premises
(`dataHandling.residency: onprem`), or who simply doesn't want telemetry
excerpts sent to a cloud model: a model server on the client's own hardware
that HELIOS's agents call instead.

- **Ollama** serves the model (or **vLLM** on a GPU server, with the `vllm`
  profile).
- **Caddy** in front of it terminates TLS and lets through only the two
  calls HELIOS makes (`POST /v1/chat/completions`, `GET /v1/models`), only
  with the box's key. Ollama's own API (pulling or deleting models) isn't
  reachable from outside.
- **Mutual TLS** (optional, recommended): the box also requires HELIOS's
  client certificate, signed by the MSSP's own CA, before it reads a
  request.

HELIOS talks to it as an OpenAI-compatible provider: structured output via
JSON schema, and tool calls for the investigation agent where the model
supports them. Replies are checked against the schema and re-asked once if
they don't match.

## Sizing

| Model | Memory for the model | Suits |
|---|---|---|
| `qwen2.5:14b` (default) | ~10 GB (GPU VRAM, or RAM on CPU) | triage, phishing, reports |
| `qwen2.5:32b` | ~20 GB | the investigation agent (tool use) |
| `llama3.3:70b` | ~43 GB | closest to the hosted models |

A 14B model runs on CPU, slowly (a minute or more per case). For more than a
handful of cases a day, use a GPU (an NVIDIA card with the memory above).
Run HELIOS's evaluation (AI page → Evaluations) against the box's model
before relying on it: a model that hasn't passed only makes suggestions.

## Install

On a Linux host with Docker:

```sh
cp .env.example .env
# AI_BOX_HOST: the name HELIOS reaches the box at
# AI_BOX_KEY:  openssl rand -hex 32
docker compose up -d
docker compose run --rm pull        # downloads AI_BOX_MODEL once
```

With an NVIDIA GPU (NVIDIA Container Toolkit installed):

```sh
docker compose -f compose.yml -f compose.gpu.yml up -d
```

vLLM instead of Ollama (GPU only): set `AI_BOX_UPSTREAM=vllm:8000`,
`AI_BOX_MODEL` to the name HELIOS should ask for and `AI_BOX_VLLM_MODEL` to
the Hugging Face model, then `docker compose --profile vllm up -d`.

Check it from another machine:

```sh
curl -s https://$AI_BOX_HOST/v1/models -H "Authorization: Bearer $AI_BOX_KEY"
curl -s -o /dev/null -w "%{http_code}\n" https://$AI_BOX_HOST/api/tags   # 401
```

## Network and certificates

`tls.caddy` decides how the box gets its certificate and whether it checks
HELIOS's. Uncomment one block in it:

1. **A public name** (DNS points at the box, ports 80 and 443 open to the
   internet for the certificate): leave the file as it is. Caddy gets a
   Let's Encrypt certificate on its own. Then restrict 443 to HELIOS's
   outbound addresses at the client's firewall.
2. **A private name or address** (reached over a VPN or private link):
   `tls internal`, Caddy's own CA. Give HELIOS that CA's root
   (`docker compose exec proxy cat /data/caddy/pki/authorities/local/root.crt`)
   as `HELIOS_AI_CA`.
3. **Mutual TLS**, with either of the above: once, the MSSP runs
   `./make-certs.sh` (somewhere safe, not on a box). It writes a CA and a
   client certificate for HELIOS.
   - **Each box:** copy `helios-ca.pem` into the box's `certs/` and uncomment block 3.
   - **HELIOS:** set `HELIOS_AI_CLIENT_CERT` and `HELIOS_AI_CLIENT_KEY` to `helios-client.pem` and `helios-client.key`.
   - **What HELIOS does:** it presents the certificate to every local (on-premises) OpenAI-compatible provider.
   - **What the box does:** it refuses the connection to anything without it. The box's key is still checked on top.
   - **The CA key:** keep `helios-ca.key` offline.

A hosted HELIOS only calls a client's own model at a public address. An
operator running HELIOS inside the client's network allows private ones with
`HELIOS_ALLOW_PRIVATE_CLIENT_AI=1`.

When the Test button fails, its message says why:
- the box wants a client certificate;
- the box didn't accept HELIOS's certificate;
- the box's certificate isn't trusted (set `HELIOS_AI_CA`);
- nothing is listening;
- the name doesn't resolve.

### Tested

The Caddyfile and `make-certs.sh` were run with Caddy 2.10 against a
stand-in model server, through HELIOS's own provider code:
- the right key and certificate connect;
- a wrong key gets 401, and paths or methods other than HELIOS's two calls get 401;
- bodies over 8 MB get 413;
- no client certificate, or one from another CA, is refused at the handshake;
- a box on Caddy's own CA is trusted only with `HELIOS_AI_CA`.

The Ollama and vLLM containers themselves weren't run here (no Docker
daemon); `docker compose config` validates the compose files.

## Connect it in HELIOS

As the client's own provider (rulebook page → AI → Add the client's own
provider):

- Kind: OpenAI-compatible endpoint
- Base URL: `https://AI_BOX_HOST/v1`
- Model: `AI_BOX_MODEL`
- API key: `AI_BOX_KEY`
- "Runs on the client's premises": on

Or for the whole platform (AI page → Providers → "HELIOS AI box"), when the
MSSP runs a box for several clients. Press **Test**: it lists the models the
box serves and says if `AI_BOX_MODEL` isn't one of them.

## Updating

```sh
docker compose pull && docker compose up -d
docker compose run --rm pull        # refresh the model
```
