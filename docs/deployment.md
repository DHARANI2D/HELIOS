# Deploying HELIOS

This guide covers:

1. Running HELIOS in containers on your Mac.
2. Running it on Kubernetes.
3. Enabling AI models, local and cloud.
4. The recommended cloud environment (AWS Mumbai) and how to set it up.
5. The security model, what to configure, and day-to-day operations.

## What ships

| Piece | Where | What it is |
| --- | --- | --- |
| Runtime image | `Dockerfile`, target `runtime` | The web server (`server.js`) and the background worker (`worker.mjs`). Distroless Debian 12, no shell or package manager, runs as user 65532. Works on a read-only root filesystem. About 160 MB compressed. |
| Tools image | `Dockerfile`, target `tools` | Applies migrations as the schema owner, then the app role's grants, then the first-run seed (`deploy/db/migrate.sh`). Distroless with a minimal busybox shell. |
| Compose stack | `docker-compose.yml` | Postgres, migrate, web and worker on one machine. Optionally an Ollama model server. |
| Development database | `docker-compose.dev.yml` | Postgres only, for `npm run dev`. |
| Kubernetes | `deploy/k8s/base`, `overlays/local`, `overlays/aws` | Kustomize manifests: Deployments, a migrate Job, Service, Ingress, autoscaler, disruption budget, network policies, Pod Security `restricted`. |
| Database roles | `deploy/db/roles.sql`, `grants.sql` | A schema owner for migrations, and an app role that can't change the schema, bypass row-level security or alter the audit log. |
| On-premises AI box | `deploy/edge-ai` | Ollama or vLLM behind Caddy with an API key and optional mutual TLS, for clients who require on-premises AI. |

Both images build for Apple Silicon (arm64) and Intel/AMD (amd64) from the same Dockerfile.

## 1. On your Mac

### What you need

- **Docker Desktop for Mac** (Apple Silicon or Intel). Give it at least 6 GB of memory and 20 GB of disk (Settings → Resources).
- **This repository**, cloned.
- **`openssl`**, which macOS already has.

### Start it

```bash
./deploy/compose/setup.sh        # writes .env.db and .env.docker with fresh secrets, prints the first admin's password
docker compose up -d --build     # builds the images (5–10 minutes the first time), then starts everything
open http://localhost:3000
```

`docker compose up` runs these in order:

1. **Postgres** starts. On first start it creates the `helios_owner` and `helios_app` roles (`deploy/db/docker-init.sh`).
2. **migrate** applies every migration as `helios_owner`, then narrows `helios_app` (`grants.sql`), then seeds reference data and the first admin. It exits when done.
3. **web** (port 3000) and **worker** start once migrate has succeeded.

Sign in as `admin@helios.local` with the password `setup.sh` printed. Then:

- change the password (Account);
- set up two-step sign-in (Account → Security);
- work through the setup checklist on the Overview.

### Everyday commands

| To | Run |
| --- | --- |
| See status | `docker compose ps` |
| Follow logs | `docker compose logs -f web worker` |
| Stop (keeps data) | `docker compose down` |
| Start again | `docker compose up -d` |
| Rebuild after pulling new code | `docker compose up -d --build` (migrations run on the way up) |
| Open the database | `psql "postgresql://postgres:<POSTGRES_PASSWORD from .env.db>@localhost:5433/helios"` |
| Start over from nothing | `docker compose down -v && rm .env.db .env.docker && ./deploy/compose/setup.sh` |

### Test data (optional)

To try HELIOS with test clients, users and cases, load the test seed. It marks the database as a test environment, and every page then shows a test banner:

```bash
docker compose run --rm -e HELIOS_ALLOW_TEST_SEED=1 --entrypoint /nodejs/bin/node migrate node_modules/tsx/dist/cli.mjs prisma/seed.ts --test
```

It prints the test accounts' passwords. Don't load it into a database you'll use for real clients.

### How the stack is locked down

These settings come with `docker-compose.yml`; nothing to configure:

- **Users and privileges:** web and worker run as an unprivileged user, with no Linux capabilities, `no-new-privileges`, and a read-only root filesystem (only `/tmp` and Next's cache are writable, in memory).
- **Ports:** the web and Postgres ports listen on `127.0.0.1` only, so other machines on your network can't reach them.
- **Network:** Postgres sits on an internal Docker network with no way out.
- **Database login:** the app signs in as `helios_app`. It can read and write rows but can't create, alter or drop tables, switch off row-level security, or change or delete audit entries. The owner's password is only in `.env.db`, which only Postgres and migrate read.
- **Secrets:** `.env.db` and `.env.docker` are created with mode 600 and are gitignored.

### Behind a company proxy

If your Mac's traffic goes through a proxy that inspects TLS (Zscaler, Netskope and the like), the build needs the proxy's CA certificate. The certificate is mounted only for the build and isn't stored in the image.

```bash
docker build --secret id=extra_ca,src=$HOME/proxy-ca.pem --target runtime -t helios:local .
docker build --secret id=extra_ca,src=$HOME/proxy-ca.pem --target tools -t helios-tools:local .
docker compose up -d
```

### Developing instead

For changing the code, run Postgres in Docker and the app natively:

```bash
docker compose -f docker-compose.dev.yml up -d
npm install
npx prisma migrate deploy
npm run db:seed
npm run dev
```

### Kubernetes on your Mac

Docker Desktop includes a single-node Kubernetes (Settings → Kubernetes → Enable). The `local` overlay runs Postgres inside the cluster, for testing only.

```bash
docker build --target runtime -t helios:local .
docker build --target tools -t helios-tools:local .
./deploy/k8s/overlays/local/secrets.sh                 # writes secrets.env and db.env (gitignored)
kubectl apply -k deploy/k8s/overlays/local
kubectl -n helios wait --for=condition=complete job/helios-migrate --timeout=10m
kubectl -n helios get pods
kubectl -n helios port-forward svc/helios-web 3000:80  # then http://localhost:3000
```

## 2. AI models

HELIOS works with no AI model at all: every agent falls back to a built-in deterministic engine. Models add analysis. Whatever the model, it never decides what runs: the response policy, the client's approved rulebook and change control do (see *How AI containment is governed* in the README).

Providers are set in the app under **AI Agents → Providers**. You can set one default for the platform and a model per agent. Each client's rulebook can restrict which models may read its evidence: any approved cloud model, region-locked, or on-premises only.

Before any model's proposals can run containment on their own, evaluate it: **AI Agents → Evaluations** scores it on the golden set. A model that hasn't passed is capped at suggestions.

### Cloud models

| Provider | When to use it | How to set it up |
| --- | --- | --- |
| **Anthropic API** (Claude) | The simplest start; strongest results on triage and investigation | Put `ANTHROPIC_API_KEY` in `.env.docker` (or the Kubernetes secret), or add an Anthropic provider in AI Agents with the key. |
| **Amazon Bedrock** (Claude in your AWS account) | Evidence stays in your AWS account and region (ap-south-1 for India); billing through AWS | Enable model access for Claude in the Bedrock console in ap-south-1 (Claude 4.7 or later). Add a Bedrock provider with the region and either an access key pair or a Bedrock API key. On EKS, prefer the pods' IAM role. |
| **Azure OpenAI** | Your organisation is on Azure (Central India) | Create a deployment. Add an Azure OpenAI provider with the resource endpoint, the deployment name and its key. |

Personal data is masked before cloud models see it, unless a client's rulebook turns masking off. Prompt caching cuts the cost of repeated agent instructions, and spend shows per run on the AI page.

### Local models on your Mac

Docker on a Mac can't use the Apple GPU, so run the model natively and let the containers reach it.

1. **Install Ollama:** the app from ollama.com, or `brew install ollama`. Start it.
2. **Pull a model that handles structured output well**, for example `ollama pull qwen2.5:14b` (needs about 16 GB of RAM) or `ollama pull llama3.1:8b` (lighter).
3. **Add a provider in HELIOS:** AI Agents → Providers → *OpenAI-compatible*, with:
   - base URL `http://host.docker.internal:11434/v1`;
   - the model name;
   - **Local** ticked.
   
   Use **Test connection**, then make it the default, or pick it for single agents.
4. **Run Evaluations** on it before relying on it.

**LM Studio** works the same way (Developer → Start server, base URL `http://host.docker.internal:1234/v1`).

To run Ollama in a container on a Linux machine with a GPU instead, use `docker compose --profile local-ai up -d`. Then:

- pull models with `docker compose exec ollama ollama pull qwen2.5:14b`;
- use the base URL `http://ollama:11434/v1`.

### On-premises models at a client's site

Use the HELIOS AI box (`deploy/edge-ai`): Ollama or vLLM on the client's own GPU server, behind Caddy. Caddy allows only the two endpoints HELIOS uses, requires an API key, can require HELIOS's client certificate (mutual TLS), and caps request size. It's the option for clients whose rulebook says *on-premises models only*. `deploy/edge-ai/README.md` has the steps.

## 3. Recommended cloud environment: AWS, Mumbai (ap-south-1)

### Why this one

- **India's rules:** CERT-In's directions want logs kept in India for 180 days, and the DPDP Act puts duties on where personal data goes. Mumbai keeps the database, the log archive, the keys and (with Bedrock) the AI in India. Hyderabad (ap-south-2) is the disaster-recovery region, also in India.
- **What HELIOS already uses:** HELIOS is built for these AWS services: KMS for its master key (`HELIOS_ENCRYPTION_KEY_KMS`), S3 for the archive, and Bedrock for Claude.
- **Managed services:** the managed database, load balancer, firewall and secrets services remove most of the patching and failover work.

If your organisation is committed elsewhere, the same design maps across. See *Other clouds* below.

### The shape of it

```
Internet ──► Route 53 ──► AWS WAF ──► Application Load Balancer (TLS 1.3, ACM certificate)
                                              │  public subnets, 3 availability zones
                                              ▼
                         ┌──────────── EKS cluster (private subnets) ────────────┐
                         │  helios-web   ×2–10  (HPA)     helios-worker ×2       │
                         │  helios-migrate Job (each release)                    │
                         │  Pod Security "restricted" · default-deny policies    │
                         └──────┬──────────────────────┬─────────────────────────┘
                                │ 5432 (TLS)           │ 443 via NAT gateway
                                ▼                      ▼
             RDS PostgreSQL 16 Multi-AZ        AI providers, security tools' APIs,
             (isolated subnets, KMS)           threat feeds, Amazon SES
                                │
      Secrets Manager ── External Secrets Operator ──► helios-secrets
      KMS (master key) · S3 archive (Object Lock) · CloudTrail · GuardDuty · Security Hub
```

### Building blocks

| Layer | Choice | Settings that matter |
| --- | --- | --- |
| Accounts | AWS Organizations; separate production and staging accounts | Service control policies: only ap-south-1 and ap-south-2; CloudTrail can't be stopped; root not used |
| Network | VPC with public, private and isolated subnets in 3 zones | One NAT gateway per zone. The database has no route to the internet. VPC flow logs on. Optionally AWS Network Firewall with an allowlist of destination domains. |
| Compute | EKS 1.31 or later, managed node groups (3 × m7g.large Graviton to start) on Bottlerocket | Private API endpoint. IMDSv2 required, hop limit 1. VPC CNI with network policy enforcement on. Pod Identity or IRSA for AWS access. |
| Simpler alternative | ECS on Fargate | The same two images: a web service behind the ALB, a worker service, and the migrate task run before each deploy |
| Database | RDS for PostgreSQL 16, Multi-AZ, db.r7g.large, gp3 storage | Encrypted with a KMS key. `rds.force_ssl=1`, and `sslmode=require` in the database URLs. Backups kept 35 days with point-in-time restore. Deletion protection. Performance Insights. |
| Secrets | Secrets Manager plus the External Secrets Operator | One secret, `helios/production`. Rotate the `helios_app` password. |
| Keys | KMS customer-managed keys | One key for HELIOS's master key (`HELIOS_ENCRYPTION_KEY_KMS`), one each for RDS and S3. Yearly rotation. |
| Edge | Route 53, ACM, Application Load Balancer, AWS WAF | TLS 1.3 policy. Invalid headers dropped. WAF managed rules: core, known bad inputs, SQL injection, IP reputation. A rate-based rule per IP, stricter on `/api/auth`. Shield Standard (Advanced if you're a target). |
| Log archive | S3 | Block Public Access, SSE-KMS, versioning, Object Lock in compliance mode for retention, lifecycle to Glacier |
| Mail | Amazon SES in ap-south-1 | Verified domain with DKIM. `HELIOS_SMTP_URL` points at SES's SMTP endpoint. |
| Detection on the platform itself | CloudTrail, GuardDuty (with EKS and RDS protection), Security Hub, AWS Config, CloudWatch Container Insights | Alerts to the SOC's own on-call |
| Images | ECR | Scan on push (Inspector). Immutable tags. Optionally sign images and verify at admission. |
| Delivery | GitHub Actions with OIDC to AWS (no stored keys) | Build both architectures, scan, push to ECR, run the migrate Job, then `kubectl apply -k` (or Argo CD) |
| Disaster recovery | ap-south-2 | RDS snapshots copied across regions. S3 replication. The same Kubernetes manifests ready there. |

### Setting it up, step by step

1. **Accounts and guardrails.**
   - Create the production account in AWS Organizations.
   - Apply region and CloudTrail service control policies.
   - Turn on CloudTrail (organisation trail), GuardDuty, Security Hub and Config.
2. **Network.** Create the VPC across three zones: public, private and isolated subnets, with a NAT gateway in each zone.
3. **Keys.** Create the KMS keys.
   - Generate HELIOS's 32-byte master key.
   - Encrypt it with the HELIOS KMS key: `aws kms encrypt --key-id … --plaintext fileb://key.bin`.
   - Keep only the base64 ciphertext; that's `HELIOS_ENCRYPTION_KEY_KMS`. Destroy `key.bin`.
4. **Database.**
   - Create the RDS instance in the isolated subnets. Its security group admits only the EKS nodes' security group, on 5432.
   - Then, from a bastion or SSM session, as the master user:
     ```bash
     psql "$MASTER_URL" -v owner_password='…' -v app_password='…' -v db=helios -f deploy/db/roles.sql
     ```
5. **Secrets.** Create `helios/production` in Secrets Manager with these keys:
   - `DATABASE_URL`: `postgresql://helios_app:…@<rds>:5432/helios?schema=public&sslmode=require`
   - `OWNER_DATABASE_URL`: the same, as `helios_owner`
   - `AUTH_SECRET`
   - `HELIOS_ENCRYPTION_KEY_KMS`
   - `SEED_ADMIN_EMAIL` and `SEED_ADMIN_PASSWORD`
   - `ANTHROPIC_API_KEY`, if you use it
6. **Cluster.**
   - Create EKS with managed Graviton nodes.
   - Install the add-ons: AWS Load Balancer Controller, External Secrets Operator (with a `ClusterSecretStore` named `aws-secrets-manager`), and EBS CSI. Turn on network policy in the VPC CNI.
7. **IAM for the pods.** Create the `helios-app` role, trusted by the `helios` service account (IRSA or Pod Identity), allowed only:
   - `kms:Decrypt` on the HELIOS key;
   - Put, Get and List on the archive bucket;
   - `bedrock:InvokeModel*` if you use Bedrock.
8. **Images.**
   - Create the `helios` and `helios-tools` ECR repositories.
   - Build and push both architectures:
     ```bash
     docker buildx build --platform linux/amd64,linux/arm64 --target runtime --build-arg HELIOS_DEPLOYMENT_ID=1.0.0 -t <ecr>/helios:1.0.0 --push .
     docker buildx build --platform linux/amd64,linux/arm64 --target tools -t <ecr>/helios-tools:1.0.0 --push .
     ```
9. **Firewall and certificate.**
   - Request the ACM certificate for your domain.
   - Create the WAF web ACL with the rules above.
10. **Deploy.**
    - Fill in every `change-me` in `deploy/k8s/overlays/aws` (`grep -rn change-me deploy/k8s/overlays/aws`): account, versions, domain, certificate and WAF ARNs, VPC CIDR, bucket.
    - Then apply and wait for the migrate Job:
      ```bash
      kubectl apply -k deploy/k8s/overlays/aws
      kubectl -n helios wait --for=condition=complete job/helios-migrate --timeout=10m
      ```
11. **DNS.** Point your domain at the load balancer (Route 53 alias).
12. **First sign-in.**
    - Change the admin password and set up two-step sign-in.
    - In Settings, require two-step sign-in for everyone and connect your SSO (`HELIOS_SSO_*`).
    - Then work through the setup checklist.
13. **Before the first client.**
    - Run a penetration test against the environment.
    - Restore a backup into staging once.
    - Put the platform's own alerts (GuardDuty, Security Hub, CloudWatch alarms) on the SOC's on-call.

### Other clouds

| Need | AWS | Azure (Central India) | Google Cloud (asia-south1) |
| --- | --- | --- | --- |
| Kubernetes | EKS | AKS | GKE Autopilot |
| PostgreSQL | RDS Multi-AZ | Database for PostgreSQL Flexible Server (zone-redundant) | Cloud SQL (high availability) |
| Secrets | Secrets Manager | Key Vault + External Secrets | Secret Manager + External Secrets |
| Keys | KMS | Key Vault keys | Cloud KMS |
| Edge firewall | ALB + WAF | Application Gateway with WAF, or Front Door | Cloud Load Balancing + Cloud Armor |
| Archive | S3 with Object Lock | Blob Storage with immutability policies | Cloud Storage with retention lock |
| AI in-region | Bedrock (Claude) | Azure OpenAI | Vertex AI |

The `base` manifests work unchanged. An overlay swaps the ingress, the secrets source and the pods' identity. HELIOS's S3 archive works with any S3-compatible store (`HELIOS_ARCHIVE_S3_ENDPOINT`). On Azure or Google Cloud, use `HELIOS_ENCRYPTION_KEY` from the secrets store in place of the AWS KMS variable.

## 4. Security model

### Built in

| Area | What HELIOS does |
| --- | --- |
| AI containment | The AI runs only initial containment on its own, inside the client's approved rulebook. A deterministic policy decides every action and records the rulebook version it decided under. Each action is checked again at the moment of acting, and a monitor stops a client's automation and pages the SOC on any violation. No AI can reach the rules. |
| Rule changes | Rulebook versions, allowlist entries, autonomy and consent rises need the client's and HELIOS's approval (platform AI limits: a second HELIOS approver). Each approval request carries a diff and a 30-day dry run, and each change is fingerprinted and audited. |
| Sign-in | Two-step sign-in (TOTP, recovery codes), which can be required for everyone. SSO with any OpenID Connect provider. Lockout after five failures. Server-side permission checks on every page and action. |
| Tenant isolation | Postgres row-level security on every client table, under the app's own filters. A client's users can't read another client's rows even if a query forgets its filter. |
| Database privileges | The app's role can't change the schema, bypass row-level security or change or delete audit entries. Partitions are managed through two owner-run functions. |
| Secrets at rest | Integration and AI keys are sealed with AES-256-GCM under a per-client data key, wrapped by the master key (AWS KMS in the cloud). |
| Audit | A hash-chained audit log; verification and export are on the Audit page. |
| Web | Every page has a Content Security Policy with a per-request nonce: no inline scripts without it, no eval, no plugins, no framing. Other headers: `nosniff`, `X-Frame-Options: DENY`, a strict referrer policy, a permissions policy, COOP/CORP, and HSTS over https. `X-Powered-By` is off. Uploads are capped at 25 MB. |
| Outbound requests | Client-entered addresses are fetched over https only, never to private or metadata addresses, with no redirects followed. Link detonation goes through a vetted proxy. In Kubernetes, egress to the metadata service and private ranges is denied by policy. |
| Visitor addresses | Only the addresses your proxies append to X-Forwarded-For are trusted (`HELIOS_TRUSTED_PROXIES`), so rate limits can't be dodged with a forged header. |
| Containers | Distroless, non-root, read-only root, no capabilities, seccomp `RuntimeDefault`, no service-account token, Pod Security `restricted`, default-deny network policies. |
| Dependencies | `npm audit --omit=dev` reports 0 known vulnerabilities in what ships. Install scripts are off in the image build except for three packages that fetch their binaries. |

### What you configure

- TLS, the WAF and its rate limits, and DNS.
- Secrets in a secrets manager, and their rotation.
- Two-step sign-in required for all staff, and SSO.
- Backups, and a tested restore.
- Monitoring of the platform itself.
- Rebuilding images monthly (or when a base-image fix lands) so the OS layer stays patched.
- A penetration test before the first client and yearly after.
- Contracts: the DPA and the liability cap for automated containment, recorded per client in Contracts & billing.

### Limits to know

No system is free of flaws, and this one is no exception. These are known and handled:

- **Rate limits for the public estimator:** they're counted per web pod, in memory. Across pods, the WAF's rate-based rules are the limit that holds. Sign-in lockout is stored in the database and holds everywhere.
- **Traffic inside the VPC:** behind the ALB, traffic to the pods is plain HTTP inside the VPC. Add a service mesh with mutual TLS if your policy requires encryption inside the VPC too.
- **Fonts at build time:** the image build downloads the Geist fonts from Google Fonts. Builds need internet access, or the fonts vendored.
- **Validation of these files:**
  - The Kubernetes manifests were validated against a real Kubernetes 1.31 API server, including Pod Security admission.
  - The compose stack was run end to end: migrations, grants, seed, sign-in, worker jobs, and the database permission checks above.
  - The EKS-specific pieces (ALB annotations, External Secrets, IRSA) follow those projects' documentation but haven't been run in an AWS account here.

## 5. Operations

### Releasing a new version

1. Build and push both images with a new tag, setting `HELIOS_DEPLOYMENT_ID` to it. Browsers holding the old pages then reload instead of mixing versions.
2. Take a database snapshot. Migrations only go forward.
3. Run the migrate Job (`kubectl delete job helios-migrate`, then `kubectl apply -k …`, then wait).
4. The web and worker Deployments roll one pod at a time. Web pods take traffic only once `/api/health` (which checks the database) answers.

**Rollback:** set the previous image tag and apply. A migration that needs undoing is restored from the snapshot taken in step 2.

### Health and scaling

- **Health checks:** `/api/health/live` is the liveness probe; it doesn't touch the database, so a database blip doesn't restart pods. `/api/health` is readiness.
- **Web scaling:** web is stateless and scales on CPU (2–10 replicas).
- **Worker scaling:** workers can run several replicas. Ingest batches are claimed with `SKIP LOCKED`, and every job is safe to run twice.

### Settings for containers

| Variable | Web | Worker | Meaning |
| --- | --- | --- | --- |
| `DATABASE_URL` | ✓ | ✓ | As `helios_app` (`sslmode=require` in the cloud) |
| `AUTH_URL` | ✓ | ✓ | The public address, e.g. `https://soc.example.com` |
| `AUTH_SECRET` | ✓ | ✓ | Session signing; 32+ random bytes |
| `HELIOS_ENCRYPTION_KEY` or `HELIOS_ENCRYPTION_KEY_KMS` | ✓ | ✓ | The master key, or its KMS ciphertext |
| `HELIOS_JOBS` | `none` | `core,ingest` | Which timed jobs the process runs |
| `HELIOS_TRUSTED_PROXIES` | ✓ | | How many proxies append to X-Forwarded-For (ALB: 1; nothing in front: 0) |
| `HELIOS_ARCHIVE_S3_BUCKET` / `_REGION` |  | ✓ | The log archive |
| `ANTHROPIC_API_KEY` | ✓ | ✓ | Optional; providers can also be set in the app |
| `HELIOS_SMTP_URL` | ✓ | ✓ | Outgoing mail (or set it in Settings) |

`.env.example` lists the rest.

### Troubleshooting

- **migrate fails with "permission denied for schema public":** `roles.sql` hasn't run on this database, or the URL isn't the owner's.
- **Web stays unready:** `/api/health` can't reach the database. Check `DATABASE_URL`, and the security group or network policy for port 5432.
- **"Failed to find Server Action" after a release:** the browser holds a page from the previous version. `HELIOS_DEPLOYMENT_ID` set at build time makes it reload on its own.
- **Local model unreachable from Docker on a Mac:** use `host.docker.internal`, not `localhost`, and check that Ollama is running (`curl localhost:11434/api/tags`).
- **The image build fails to download packages behind a company proxy:** pass the proxy's CA certificate as the `extra_ca` build secret (see above).
