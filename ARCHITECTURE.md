# CTFchalls2026 - Distributed Architecture on AWS EC2

## Overview

This CTF platform is deployed across **3 AWS EC2 free-tier instances** to prevent OOM (Out of Memory) errors and distribute workload efficiently. All services are secured with **Traefik reverse proxy** providing **automatic HTTPS** via **Let's Encrypt**.

---

## Architecture Diagram

```
                                 ┌─────────────────────────────────┐
                                 │      DNS Configuration          │
                                 │  ctf.dscjssstuniv.in            │
                                 │  *.ctf.dscjssstuniv.in          │
                                 │  *.challenges1.ctf.dscjssstuniv │
                                 │  *.challenges2.ctf.dscjssstuniv │
                                 └─────────────────────────────────┘
                                              │
                 ┌────────────────────────────┼────────────────────────────┐
                 │                            │                            │
                 ▼                            ▼                            ▼
        ┌────────────────┐          ┌────────────────┐          ┌────────────────┐
        │   EC2-1 (Core) │          │ EC2-2 (Light)  │          │ EC2-3 (Heavy)  │
        │   t2.micro     │          │   t2.micro     │          │   t2.micro     │
        └────────────────┘          └────────────────┘          └────────────────┘
                 │                            │                            │
                 │                            │                            │
        ┌────────▼────────┐          ┌────────▼────────┐          ┌────────▼────────┐
        │    Traefik      │          │    Traefik      │          │    Traefik      │
        │  (HTTPS + LB)   │          │  (HTTPS + LB)   │          │  (HTTPS + LB)   │
        │  Ports: 80,443  │          │  Ports: 80,443  │          │  Ports: 80,443  │
        └─────────────────┘          └─────────────────┘          └─────────────────┘
                 │                            │                            │
     ┌───────────┼───────────┐                │                            │
     │           │           │                │                            │
     ▼           ▼           ▼                ▼                            ▼
┌─────────┐ ┌─────────┐ ┌─────────┐  ┌─────────────┐            ┌─────────────────┐
│  CTFd   │ │MariaDB  │ │  Redis  │  │5 Coding     │            │2 PWN (mem limit)│
│Platform │ │Database │ │  Cache  │  │1 Crypto     │            │3 Pyjail (limits)│
└─────────┘ └─────────┘ └─────────┘  │2 Reverse    │            │3 Reverse (heavy)│
     │                                │2 Misc       │            │1 Misc (SSH)     │
     └──────────────────┐             └─────────────┘            └─────────────────┘
                        │
                        ▼
              ┌──────────────────┐
              │  12 Web Services │
              │  (Light HTTP)    │
              └──────────────────┘
```

---

## EC2 Instance Breakdown

### **EC2-1: Core Infrastructure + Web Challenges**

**Instance Type:** AWS EC2 t2.micro (1 vCPU, 1GB RAM)  
**Domain:** `ctf.dscjssstuniv.in` / `*.ctf.dscjssstuniv.in`  
**Compose File:** `docker-compose.ec2-1.yml`

#### Services (16 containers)

**Infrastructure:**

- `traefik` - Reverse proxy with HTTPS (ports 80, 443, 8080)
- `ctfd` - Main CTF platform
- `db` - MariaDB 10.11 database
- `cache` - Redis 4 cache

**Web Challenges (12):**

1. `wrong_password` - https://wrongpassword.ctf.dscjssstuniv.in
2. `secure_portal` - https://secureportal.ctf.dscjssstuniv.in
3. `cookie_recipe` - https://cookierecipe.ctf.dscjssstuniv.in
4. `curl_unfurl` - https://curlunfurl.ctf.dscjssstuniv.in
5. `robots_watching` - https://robotswatching.ctf.dscjssstuniv.in
6. `time_window` - https://timewindow.ctf.dscjssstuniv.in
7. `stranger_things` - https://stranger.ctf.dscjssstuniv.in
8. `overthinker` - https://overthinker.ctf.dscjssstuniv.in
9. `plain_sight` - https://plainsight.ctf.dscjssstuniv.in
10. `flag_in_cache` - https://flagcache.ctf.dscjssstuniv.in
11. `auth_adventure` - https://auth.ctf.dscjssstuniv.in
12. `nothing_works` - https://nothingworks.ctf.dscjssstuniv.in

**Why This Distribution:**

- Web challenges are lightweight HTTP services (Flask/FastAPI)
- CTFd needs persistent database/cache - keeps them together
- Minimal memory footprint per web container (~50-100MB)

---

### **EC2-2: Coding + Crypto + Light Challenges**

**Instance Type:** AWS EC2 t2.micro (1 vCPU, 1GB RAM)  
**Domain:** `*.challenges1.ctf.dscjssstuniv.in`  
**Compose File:** `docker-compose.ec2-2.yml`

#### Services (11 containers)

**Infrastructure:**

- `traefik` - Reverse proxy with HTTPS

**Coding Challenges (5):**

1. `pathfinding_puzzle` - https://pathfinding.challenges1.ctf.dscjssstuniv.in
2. `regex_master` - https://regex.challenges1.ctf.dscjssstuniv.in
3. `tree_traversal` - https://tree.challenges1.ctf.dscjssstuniv.in
4. `coding_numbers` - https://numbers.challenges1.ctf.dscjssstuniv.in
5. `math_challenge` - https://math.challenges1.ctf.dscjssstuniv.in

**Cryptography (1):** 6. `caesars_pizza` - https://caesar.challenges1.ctf.dscjssstuniv.in

**Light Reverse Engineering (2):** 7. `license_checker` - https://license.challenges1.ctf.dscjssstuniv.in 8. `endgame_protocol` - https://endgame.challenges1.ctf.dscjssstuniv.in

**Light Misc (2):** 9. `echo_chamber` - https://echochamber.challenges1.ctf.dscjssstuniv.in 10. `formality_breach` - https://formalitybreach.challenges1.ctf.dscjssstuniv.in

**Why This Distribution:**

- Coding challenges are CPU-bound but short-lived (timeouts)
- Crypto and light reverse are HTTP-based, low memory
- Balanced workload with predictable resource usage

---

### **EC2-3: Heavy Workloads (PWN + Pyjail + Heavy Reverse)**

**Instance Type:** AWS EC2 t2.micro (1 vCPU, 1GB RAM)  
**Domain:** `*.challenges2.ctf.dscjssstuniv.in`  
**Compose File:** `docker-compose.ec2-3.yml`

#### Services (10 containers)

**Infrastructure:**

- `traefik` - Reverse proxy with HTTPS

**Binary Exploitation (2):**

1. `menu_pwner` - nc menupwner.challenges2.ctf.dscjssstuniv.in 9999
   - `mem_limit: 256m`, `cpus: 0.5`, port 9999 exposed
2. `overflow_academy` - nc overflow.challenges2.ctf.dscjssstuniv.in 9001
   - `mem_limit: 256m`, `cpus: 0.5`, port 9001 exposed

**Heavy Reverse Engineering (3):** 3. `upside_down` - nc upsidedown.challenges2.ctf.dscjssstuniv.in 1339

- `mem_limit: 256m`, `cpus: 0.5`, port 1339 exposed

4. `has_to_echo` - nc hastoecho.challenges2.ctf.dscjssstuniv.in 1340
   - `mem_limit: 256m`, `cpus: 0.5`, port 1340 exposed
5. `conditions` - nc conditions.challenges2.ctf.dscjssstuniv.in 42552
   - `mem_limit: 256m`, `cpus: 0.5`, port 42552 exposed

**Pyjail (3):** 6. `cipher_prison` - nc cipherprison.challenges2.ctf.dscjssstuniv.in 1337

- `mem_limit: 256m`, `cpus: 0.5`, `pids_limit: 100`, port 1337 exposed

7. `prison_break` - nc prisonbreak.challenges2.ctf.dscjssstuniv.in 9999
   - `mem_limit: 256m`, `cpus: 0.5`, `pids_limit: 100`, port 9998 exposed
8. `blacklist_hell` - nc blacklisthell.challenges2.ctf.dscjssstuniv.in 1338
   - `mem_limit: 256m`, `cpus: 0.5`, `pids_limit: 100`, port 1338 exposed

**Heavy Misc (1):** 9. `missing_tools` - ssh ctfplayer@missingtools.challenges2.ctf.dscjssstuniv.in -p 22

- `mem_limit: 256m`, `cpus: 0.5`, port 2222 exposed

**Why This Distribution:**

- All containers have resource limits to prevent OOM
- PWN and pyjail are high-risk for resource abuse
- TCP-based services need dedicated ports (not HTTP)
- Heavy reverse challenges use more CPU/memory

---

## Traefik Configuration

All 3 instances use identical Traefik setup:

### Features

- **Automatic HTTPS:** Let's Encrypt HTTP-01 challenge
- **HTTP → HTTPS Redirect:** All HTTP traffic redirected to HTTPS
- **Dynamic routing:** Docker label-based configuration
- **Dashboard:** Port 8080 (insecure mode for monitoring)

### Key Configuration

```yaml
command:
  - "--providers.docker.exposedbydefault=false"
  - "--entrypoints.web.address=:80"
  - "--entrypoints.websecure.address=:443"
  - "--entrypoints.web.http.redirections.entrypoint.to=websecure"
  - "--certificatesresolvers.le.acme.email=admin@dscjssstuniv.in"
  - "--certificatesresolvers.le.acme.storage=/letsencrypt/acme.json"
  - "--certificatesresolvers.le.acme.httpchallenge=true"
```

### Per-Service Labels (Example)

```yaml
labels:
  - "traefik.enable=true"
  - "traefik.http.routers.ctfd.rule=Host(`ctf.dscjssstuniv.in`)"
  - "traefik.http.routers.ctfd.entrypoints=websecure"
  - "traefik.http.routers.ctfd.tls=true"
  - "traefik.http.routers.ctfd.tls.certresolver=le"
  - "traefik.http.services.ctfd.loadbalancer.server.port=8000"
```

---

## DNS Configuration

Add these records to your DNS provider:

| Record Type | Hostname                           | Value           | TTL |
| ----------- | ---------------------------------- | --------------- | --- |
| A           | ctf.dscjssstuniv.in                | EC2-1-PUBLIC-IP | 300 |
| A           | \*.ctf.dscjssstuniv.in             | EC2-1-PUBLIC-IP | 300 |
| A           | \*.challenges1.ctf.dscjssstuniv.in | EC2-2-PUBLIC-IP | 300 |
| A           | \*.challenges2.ctf.dscjssstuniv.in | EC2-3-PUBLIC-IP | 300 |

---

## Deployment Instructions

### Prerequisites (on each EC2 instance)

```bash
# Install Docker and Docker Compose
sudo apt update
sudo apt install -y docker.io docker-compose
sudo systemctl enable docker
sudo systemctl start docker
sudo usermod -aG docker $USER
```

### Deploy EC2-1 (Core + Web)

```bash
# SSH into EC2-1
ssh -i your-key.pem ubuntu@ec2-1-public-ip

# Clone repository
git clone https://github.com/Pranavbarathi05/CTFchalls2026.git
cd CTFchalls2026

# Prepare Let's Encrypt storage
mkdir -p letsencrypt
touch letsencrypt/acme.json
chmod 600 letsencrypt/acme.json

# Update ACME email in docker-compose.ec2-1.yml
sed -i 's/admin@dscjssstuniv.in/your-email@example.com/g' docker-compose.ec2-1.yml

# Deploy
docker compose -f docker-compose.ec2-1.yml up -d --build

# Verify
docker ps
docker logs traefik
```

### Deploy EC2-2 (Coding + Crypto)

```bash
# SSH into EC2-2
ssh -i your-key.pem ubuntu@ec2-2-public-ip

# Clone repository
git clone https://github.com/Pranavbarathi05/CTFchalls2026.git
cd CTFchalls2026

# Prepare Let's Encrypt storage
mkdir -p letsencrypt
touch letsencrypt/acme.json
chmod 600 letsencrypt/acme.json

# Update ACME email
sed -i 's/admin@dscjssstuniv.in/your-email@example.com/g' docker-compose.ec2-2.yml

# Deploy
docker compose -f docker-compose.ec2-2.yml up -d --build
```

### Deploy EC2-3 (Heavy Workloads)

```bash
# SSH into EC2-3
ssh -i your-key.pem ubuntu@ec2-3-public-ip

# Clone repository
git clone https://github.com/Pranavbarathi05/CTFchalls2026.git
cd CTFchalls2026

# Prepare Let's Encrypt storage
mkdir -p letsencrypt
touch letsencrypt/acme.json
chmod 600 letsencrypt/acme.json

# Update ACME email
sed -i 's/admin@dscjssstuniv.in/your-email@example.com/g' docker-compose.ec2-3.yml

# Deploy
docker compose -f docker-compose.ec2-3.yml up -d --build
```

---

## Security Best Practices

### Implemented

- ✅ **Traefik exposedbydefault=false** - Prevents accidental exposure
- ✅ **Docker socket read-only** - `/var/run/docker.sock:/var/run/docker.sock:ro`
- ✅ **Resource limits** - Memory/CPU caps on heavy containers
- ✅ **Non-root users** - Most services run as non-root
- ✅ **Security options** - `no-new-privileges:true` on PWN/pyjail
- ✅ **PID limits** - `pids_limit: 100` on pyjail containers

### Recommended (Not Implemented)

- 🔒 **Firewall rules** - Allow only 80, 443, and specific challenge ports
- 🔒 **Rate limiting** - Traefik middleware for DDoS protection
- 🔒 **Healthchecks** - Docker HEALTHCHECK directives
- 🔒 **Monitoring** - Prometheus + Grafana for metrics
- 🔒 **Log aggregation** - Centralized logging (ELK/Loki)
- 🔒 **Backup strategy** - Automated CTFd database backups

---

## Resource Allocation

| Instance | Containers | Est. Memory | Est. CPU | Risk Level |
| -------- | ---------- | ----------- | -------- | ---------- |
| EC2-1    | 16         | ~800MB      | ~30%     | Low        |
| EC2-2    | 11         | ~650MB      | ~40%     | Low        |
| EC2-3    | 10         | ~900MB      | ~60%     | Medium     |

**Total:** 37 containers across 3 instances

### Memory Breakdown (EC2-3 - Heaviest)

- Traefik: ~50MB
- 2 PWN containers: 2 × 256MB = 512MB (capped)
- 3 Pyjail containers: 3 × 256MB = 768MB (capped) - **but limited to 256MB total**
- 3 Reverse containers: 3 × 256MB = 768MB (capped) - **but limited to 256MB total**
- 1 Misc (SSH): 1 × 256MB = 256MB (capped)

**Actual max usage:** ~550MB with all limits enforced

---

## Monitoring & Troubleshooting

### Check Service Status

```bash
# On each EC2 instance
docker ps
docker compose -f docker-compose.ec2-X.yml ps
```

### View Logs

```bash
# Traefik logs
docker logs traefik -f

# Specific challenge
docker logs <container_name> -f

# All services
docker compose -f docker-compose.ec2-X.yml logs -f
```

### Restart Services

```bash
# Single service
docker restart <container_name>

# All services
docker compose -f docker-compose.ec2-X.yml restart

# Rebuild and restart
docker compose -f docker-compose.ec2-X.yml up -d --build
```

### Check Traefik Dashboard

```
http://ec2-public-ip:8080
```

### Let's Encrypt Certificate Status

```bash
# Check acme.json
cat letsencrypt/acme.json | jq '.le.Certificates'

# Force renewal
docker exec traefik traefik --acme.force
```

---

## Cost Analysis

### AWS EC2 Free Tier (12 months)

- **Instance Type:** t2.micro (1 vCPU, 1GB RAM)
- **Quantity:** 3 instances
- **Cost:** $0/month (within 750 hours/month free tier)

### Post Free-Tier Cost (Estimated)

- 3 × t2.micro (us-east-1): ~$7.50/month
- Data transfer: ~$5-10/month (depends on traffic)
- **Total:** ~$12-17/month

### Cost Optimization Recommendations

- Use AWS Reserved Instances for 30-40% savings
- Enable CloudWatch monitoring to track usage
- Implement auto-scaling (though not needed for CTF)

---

## Performance Considerations

### Load Balancing

- **Current:** Single Traefik per instance (no multi-instance LB)
- **For high traffic:** Consider AWS ALB or Cloudflare in front

### Scaling

- **Horizontal:** Add more EC2 instances for specific categories
- **Vertical:** Upgrade to t2.small (2GB RAM) if needed

### Caching

- Redis cache on EC2-1 reduces CTFd database load
- Consider CloudFlare for static asset caching

---

## Future Enhancements

1. **Automated Backups**
   - Cron job for CTFd database dumps
   - S3 bucket for backup storage

2. **CI/CD Pipeline**
   - GitHub Actions for automated deployment
   - Terraform for infrastructure as code

3. **Monitoring Stack**
   - Prometheus for metrics
   - Grafana for dashboards
   - Alert manager for notifications

4. **DDoS Protection**
   - Cloudflare proxy
   - Traefik rate limiting middleware

5. **High Availability**
   - Multi-region deployment
   - Database replication
   - Load balancer with health checks

---

## Conclusion

This architecture balances:

- ✅ **Cost efficiency** - Uses AWS free tier
- ✅ **Resource optimization** - Prevents OOM with distribution
- ✅ **Security** - HTTPS, resource limits, non-root users
- ✅ **Scalability** - Easy to add more instances
- ✅ **Maintainability** - Clean separation of concerns

**Total Deployment Time:** ~30 minutes (assuming DNS is pre-configured)

**Maintenance Effort:** Low - Docker Compose handles restarts, Traefik auto-renews certificates

---

## Support & Contact

- **Repository:** https://github.com/Pranavbarathi05/CTFchalls2026
- **Issues:** https://github.com/Pranavbarathi05/CTFchalls2026/issues
- **Documentation:** See challenge-specific README.md files in each directory

**Last Updated:** 2026-01-26
