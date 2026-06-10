# Redis — Caché de intelli-dns

Redis corre en la misma VM que PostgreSQL. Su única función es guardar en RAM tres cosas:

| Qué | Clave (Key) | TTL |
|-----|-------------|-----|
| Dominio malicioso | `domain:<nombre>` | 24 h |
| Stats globales | `stats:global` | 5 min |
| Whitelist de dominios conocidos | `whitelist:domains` (Set) | Sin expiración |

---

## Despliegue

```bash
docker-compose up -d
```

Esto levanta **Postgres en 5432** y **Redis en 6379**, ambos enlazados a la red privada de la VM. Nadie desde internet puede alcanzarlos.

### Variables de entorno (`.env` en esta carpeta)

```env
DB_BIND_IP=10.0.0.5       # IP privada de la VM
REDIS_BIND_IP=10.0.0.5
DB_NAME=intellidns
DB_USER=intellidns_admin
DB_PASSWORD=tuPasswordSegura

REDIS_HOST=10.0.0.5
REDIS_PORT=6379
REDIS_PASSWORD=tuPasswordSeguraDeRedis
```

---

## Cargar la whitelist (solo una vez al desplegar)

```bash
node load-whitelist.js
```

Lee el archivo `tranco_top1m_domains.csv` y carga el millón de dominios en el Set `whitelist:domains` de Redis en lotes de 10 000. Tarda unos segundos. Solo necesitas correrlo una vez, o cuando actualices el CSV.

---

## Cómo el backend Express llama a Redis

El backend usa la librería **`ioredis`**. Estas son las tres operaciones concretas:

### 1. Verificar whitelist antes de clasificar

```js
// Antes de llamar al modelo ML, chequear si es un dominio conocido
const isWhitelisted = await redis.sismember('whitelist:domains', domain);
if (isWhitelisted) {
  return { verdict: 'benign', confidence: 1.0, source: 'whitelist' };
}
```

### 2. Cache-Aside para dominios maliciosos

```js
// Intentar leer del caché
const cached = await redis.get(`domain:${domain}`);
if (cached) {
  return { ...JSON.parse(cached), source: 'cache' };
}

// Si no está → llamar al modelo ML y a la BD
const result = await callModelML(domain);
await db.query('SELECT fn_upsert_domain($1,$2,$3)', [domain, result.verdict, result.confidence]);

// Solo guardar en Redis si es malicioso
if (result.verdict === 'malicious') {
  await redis.setex(`domain:${domain}`, 86400, JSON.stringify({
    verdict: result.verdict,
    confidence: result.confidence
  }));
}
```

### 3. Stats globales con caché de 5 minutos

```js
const cached = await redis.get('stats:global');
if (cached) return JSON.parse(cached);

// Si no está → calcular desde Postgres
const { rows } = await db.query('SELECT * FROM fn_stats_global()');
await redis.setex('stats:global', 300, JSON.stringify(rows[0]));
return rows[0];
```

### 4. Invalidar caché al reclasificar un dominio

```js
// Cuando un admin cambia el veredicto de un dominio
await db.query('SELECT fn_upsert_domain($1,$2,$3)', [domain, newVerdict, confidence]);
await redis.del(`domain:${domain}`); // Borrar del caché para que se recalcule
```

---

## Seguridad de red (UFW en la VM)

```bash
sudo ufw default deny incoming
sudo ufw allow 22/tcp
sudo ufw allow from <IP_PRIVADA_BACKEND> to any port 5432 proto tcp
sudo ufw allow from <IP_PRIVADA_BACKEND> to any port 6379 proto tcp
sudo ufw enable
```
