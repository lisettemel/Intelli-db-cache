# Redis — Caché de intelli-dns

Redis corre en la misma VM que PostgreSQL. Su única función es guardar en RAM dos cosas:

| Qué | Clave (Key) | TTL |
|-----|-------------|-----|
| Veredicto de dominio (malicioso **y** benigno) | `verdict:<dominio>` | 24 h |
| Stats globales | `stats:global` | 5 min |

El backend además usa el prefijo `rl:*` para su rate limiting (express-rate-limit con store de Redis); esas claves las administra él.

Los veredictos `unknown` (ML caído) **no se cachean**: son transitorios y deben reintentar contra el ML en el siguiente check.

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

> `redis.conf` exige auth (`requirepass`). El backend debe mandar la misma
> password vía su variable `REDIS_PASSWORD`.

---

## Cómo el backend Express llama a Redis

El backend usa la librería **`ioredis`**. Estas son las operaciones concretas:

### 1. Cache-Aside de veredictos (ambos: malicious y benign)

```js
// Intentar leer del caché
const cached = await redis.get(`verdict:${domain}`);
if (cached) {
  return { ...JSON.parse(cached), cached: true };
}

// Si no está → llamar al modelo ML y a la BD
const result = await callModelML(domain);
await db.query('SELECT fn_upsert_domain($1,$2,$3)', [domain, result.verdict, result.confidence]);

// Cachear malicious Y benign (unknown nunca se cachea)
if (result.verdict !== 'unknown') {
  await redis.setex(`verdict:${domain}`, 86400, JSON.stringify({
    verdict: result.verdict,
    confidence: result.confidence
  }));
}
```

### 2. Stats globales con caché de 5 minutos

```js
const cached = await redis.get('stats:global');
if (cached) return JSON.parse(cached);

// Si no está → calcular desde Postgres
const { rows } = await db.query('SELECT * FROM fn_stats_global()');
await redis.setex('stats:global', 300, JSON.stringify(rows[0]));
return rows[0];
```

### 3. Invalidar caché al reclasificar un dominio

```js
// Cuando un admin cambia el veredicto de un dominio
await db.query('SELECT fn_upsert_domain($1,$2,$3)', [domain, newVerdict, confidence]);
await redis.del(`verdict:${domain}`); // Borrar del caché para que se recalcule
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
