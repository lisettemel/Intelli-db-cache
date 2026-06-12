# Intelli-db-cache

Capa de base de datos y caché para **intelli-dns** — un sistema inteligente de seguridad DNS que clasifica dominios como maliciosos, benignos o desconocidos mediante un modelo de machine learning. Este repositorio contiene el esquema de PostgreSQL, las funciones almacenadas, la configuración de Redis como caché y el despliegue con Docker Compose.

---

## Arquitectura

La base de datos y la caché están diseñadas como una capa de persistencia y rendimiento desacoplada, corriendo en contenedores aislados.```
┌────────────────┐     ┌──────────────────────────────────────────────┐
│  Extensión de  │────▶│  Backend Express (repositorio separado)       │
│  Navegador     │     │                                              │
│  (intelli-dns) │     │  1. Revisar caché de veredictos en Redis     │
└────────────────┘     │  2. Si MISS → llamar al modelo ML → guardar │
                       │  3. Cachear veredicto (si no es unknown)     │
                       │  4. Registrar evento → devolver veredicto    │
                       └──────────┬──────────────┬────────────────────┘
                                  │              │
                       ┌──────────▼──────┐  ┌────▼─────────────┐
                       │  Redis (caché)  │  │  PostgreSQL (BD) │
                       │  Puerto 6379    │  │  Puerto 5432     │
                       │  256 MB RAM     │  │  Persistente     │
                       └─────────────────┘  └──────────────────┘
                       ▲                    ▲
                       │  ESTE REPOSITORIO  │
                       └────────────────────┘
```

Tanto PostgreSQL como Redis corren en la **misma VM** dentro de contenedores Docker, conectados por una red bridge privada (`intellidns_net`). Ninguno está expuesto a internet.

---

## Estructura del Proyecto

```
Intelli-db-cache/
├── .gitignore                  # Archivos excluidos del control de versiones
├── LICENSE                     # Licencia MIT (Lisette Melo Reyes, 2026)
├── README.md                   # Este archivo
│
├── database/                   # Esquema y funciones de PostgreSQL
│   ├── schema.sql              # Tablas, tipos e índices (diseño 3NF)
│   └── functions.sql           # 8 funciones PL/pgSQL llamadas por el backend
│
└── cache/                      # Caché Redis + orquestación Docker
    ├── README.md               # Documentación detallada del caché
    ├── docker-compose.yml      # Define los contenedores de Postgres + Redis
    ├── redis.conf              # Configuración endurecida de Redis
    ├── package.json            # Dependencias de Node (ioredis, dotenv)
    ├── package-lock.json       # Versiones bloqueadas de dependencias
    └── data/
        └── tranco_top1m_domains.csv  # Top 1M dominios conocidos (~22 MB)
```

---

## Base de Datos — `database/`

Estos archivos SQL se ejecutan automáticamente en el contenedor de PostgreSQL durante el primer arranque. Docker Compose los monta en `/docker-entrypoint-initdb.d/` con orden explícito:
- `01_schema.sql` ← `schema.sql`
- `02_functions.sql` ← `functions.sql`

### `schema.sql` — Tablas y Tipos

Define el esquema normalizado (3NF) de la base de datos. **No se almacena ningún dato personal por diseño.**

#### Tipos Enumerados

| Tipo | Valores | Propósito |
|------|---------|-----------|
| `verdict_enum` | `malicious`, `benign`, `unknown` | Resultado de clasificación del modelo ML |
| `report_enum` | `false_positive`, `false_negative` | Tipo de retroalimentación del usuario |

#### Tablas

| Tabla | Propósito | Columnas Clave |
|-------|-----------|----------------|
| **`users`** | Identidades anónimas de usuarios | `anon_id` (hash SHA-256, 64 caracteres hex) — sin datos personales |
| **`domains`** | Catálogo de todos los dominios vistos | `domain` (único), `verdict`, `confidence`, `last_classified` |
| **`domain_features`** | 6 features del ML por dominio (1-a-1 con `domains`) | 3 léxicas + 3 DNS (ver abajo) |
| **`check_events`** | Bitácora — una fila por cada llamada a `/check` | `anon_id` → `users`, `domain_id` → `domains`, flag `was_cached` |
| **`reports`** | Reportes de falsos positivos/negativos enviados por usuarios | Enlaza `anon_id` + `domain_id` + `report_type`; **no** cambia veredictos automáticamente |

#### Features de Dominios (6 columnas en `domain_features`)

Estas coinciden exactamente con las features calculadas por el modelo ML (`intelli-dns src/model/features.py`):

| Columna | Tipo | Categoría | Descripción |
|---------|------|-----------|-------------|
| `domain_length` | `INTEGER` | Léxica | Longitud total del string del dominio |
| `num_dots` | `INTEGER` | Léxica | Cantidad de puntos en el dominio |
| `has_suspicious_keyword` | `SMALLINT` | Léxica | Flag 0/1 — contiene un token sospechoso |
| `num_a_records` | `INTEGER` | DNS | Cantidad de direcciones IP asociadas al dominio (registro A). Un valor de 0 significa que el dominio no resuelve a ninguna IP (NXDOMAIN / dominio inexistente) |
| `num_ns_records` | `INTEGER` | DNS | Cantidad de servidores de nombres (NS) que administran el dominio. Un valor de 0 indica que no se encontraron servidores DNS autoritativos (NXDOMAIN / dominio inexistente) |
| `has_txt` | `SMALLINT` | DNS | Flag 0/1 — indica si el dominio tiene un registro TXT (usado comúnmente para verificación de propiedad, SPF de correo, etc.). Los dominios maliciosos rara vez lo configuran |

#### Índices

| Índice | Sobre | Propósito |
|--------|-------|-----------|
| `idx_check_events_anon` | `check_events(anon_id)` | Búsquedas rápidas de estadísticas por usuario |
| `idx_check_events_time` | `check_events(checked_at)` | Consultas por rango de tiempo |
| `idx_check_events_domain` | `check_events(domain_id)` | Búsquedas de actividad por dominio |
| `idx_reports_domain` | `reports(domain_id)` | Reportes por dominio |

> **Nota:** `domains(domain)` ya está indexado por su restricción `UNIQUE`.

---

### `functions.sql` — Funciones Almacenadas

Ocho funciones PL/pgSQL consumidas por la API Express del backend mediante `SELECT * FROM fn_nombre(...)`:

| # | Función | Llamada por | Qué hace |
|---|---------|-------------|----------|
| 1 | `fn_register_user(anon_id)` | `POST /register` | Inserta un nuevo usuario anónimo. Devuelve `'registered'` o `'collision'` si el ID ya existe. |
| 2 | `fn_upsert_domain(domain, verdict, confidence)` | `POST /check` | Inserta o actualiza el veredicto de un dominio. **Comportamiento especial para `unknown`:** NO sobrescribe un veredicto real existente — solo asegura que exista la fila del dominio para poder registrar el evento. |
| 3 | `fn_save_features(domain_id, domain_length, num_dots, has_suspicious_keyword, num_a_records, num_ns_records, has_txt)` | `POST /check` | Guarda o actualiza las 6 features del ML para un dominio (upsert 1-a-1). |
| 4 | `fn_log_check(anon_id, domain_id, was_cached)` | `POST /check` | Registra un evento de chequeo en la bitácora. Devuelve `event_id`. |
| 5 | `fn_save_report(anon_id, domain_id, report_type)` | `POST /report` | Guarda un reporte de falso positivo/negativo. **No** cambia el veredicto. Devuelve `report_id`. |
| 6 | `fn_stats_me(anon_id)` | `GET /stats/me` | Devuelve estadísticas personales: total chequeados, conteo de maliciosos, benignos, desconocidos, y fecha del primer chequeo. |
| 7 | `fn_stats_me_history(anon_id, limit, offset)` | `GET /stats/me/history` | Devuelve historial de chequeos paginado para un usuario. Incluye `total_count` (vía función ventana) para que el cliente pueda paginar sin un segundo round-trip. |
| 8 | `fn_stats_global()` | `GET /stats/global` | Devuelve estadísticas globales agregadas: total de dominios, total de chequeos, conteos de maliciosos/benignos, y tasa de detección como **fracción (0–1)**, no porcentaje. El backend cachea el resultado en Redis por 5 minutos. |

---

## Caché — `cache/`

### `docker-compose.yml` — Servicios

Define dos contenedores Docker en una red bridge compartida (`intellidns_net`):

| Servicio | Imagen | Nombre del Contenedor | Puerto | Datos |
|----------|--------|-----------------------|--------|-------|
| **db** (PostgreSQL) | `postgres:16-alpine` | `intellidns_postgres` | `5432` | Persistidos en volumen Docker `postgres_data` |
| **redis** (Redis) | `redis:7-alpine` | `intellidns_redis` | `6379` | Solo en memoria (sin persistencia) |

Comportamientos clave:
- En el primer arranque, PostgreSQL ejecuta automáticamente `schema.sql` y luego `functions.sql` (montados como `01_schema.sql` y `02_functions.sql` en modo solo lectura).
- Ambos servicios se enlazan a `127.0.0.1` por defecto (seguro para desarrollo local). En producción, se configura `DB_BIND_IP` y `REDIS_BIND_IP` en `.env` con la IP privada de la VM.
- `DB_PASSWORD` y `REDIS_PASSWORD` son **obligatorios** — docker-compose fallará si no están definidos (usa sintaxis `${VAR:?}`).
- La contraseña de Redis **no está hardcodeada** en `redis.conf`. Se inyecta en tiempo de ejecución mediante el flag `--requirepass` en el comando de docker-compose.
- Ambos servicios se reinician automáticamente a menos que se detengan manualmente (`restart: unless-stopped`).

---

### `redis.conf` — Configuración de Redis

Configuración endurecida y optimizada para caché:

| Configuración | Valor | Por qué |
|---------------|-------|---------|
| `bind` | `0.0.0.0` | Escucha en todas las interfaces dentro del contenedor (el acceso se restringe por el mapeo de puertos de Docker + firewall) |
| `protected-mode` | `yes` | Requiere autenticación para las conexiones |
| `save ""` | deshabilitado | **Sin persistencia en disco (RDB desactivado)** — evita competir con PostgreSQL por I/O de disco |
| `appendonly` | `no` | **Sin persistencia AOF** — caché puro en memoria |
| `maxmemory` | `256mb` | Límite máximo de uso de RAM para Redis |
| `maxmemory-policy` | `allkeys-lru` | Desaloja las llaves menos recientemente usadas cuando la memoria se llena |
| `maxmemory-samples` | `5` | Balance ideal entre rendimiento y precisión del algoritmo LRU |
| `activedefrag` | `yes` | Desfragmenta la memoria automáticamente en segundo plano |

Comandos peligrosos **renombrados a vacío** (deshabilitados): `FLUSHDB`, `FLUSHALL`, `CONFIG`, `SHUTDOWN`, `DEBUG`.

> **Nota sobre la contraseña:** La directiva `requirepass` está intencionalmente ausente de `redis.conf` para evitar hardcodear secretos en git. La contraseña se inyecta desde docker-compose usando la variable de entorno `REDIS_PASSWORD` mediante el flag `--requirepass`.

---

### `package.json` — Dependencias de Node

| Dependencia | Versión | Propósito |
|-------------|---------|-----------|
| `ioredis` | `^5.11.1` | Cliente de Redis para Node.js |
| `dotenv` | `^17.4.2` | Carga archivos `.env` en `process.env` |

Estas dependencias son usadas por utilidades o scripts del backend que interactúan con Redis.

---

### `data/tranco_top1m_domains.csv` — Whitelist de Dominios

Un archivo CSV de ~22 MB que contiene el **top 1 millón de dominios de Tranco** (un ranking de investigación reconocido de dominios populares). Formato:

```csv
1,google.com
2,facebook.com
3,youtube.com
...
```

> Este archivo está listado en `.gitignore` por su tamaño. Descárgalo desde [Tranco List](https://tranco-list.eu/) si lo necesitas.

---

## Integración y Conexión con otros Sistemas

Esta capa de datos no se expone a internet. Solo interactúa directamente con el Backend de la siguiente manera:

### Uso de Redis por el Backend

Redis almacena dos tipos de datos en memoria, más llaves de rate limiting administradas por el backend:

| Qué | Clave Redis | Tipo | TTL | Propósito |
|-----|-------------|------|-----|-----------|
| Caché de veredictos | `verdict:<dominio>` | String (JSON) | 24 horas | Cachear veredictos del ML para evitar llamadas de clasificación repetidas |
| Estadísticas globales | `stats:global` | String (JSON) | 5 minutos | Cachear consultas agregadas costosas de PostgreSQL |
| Rate limiting | `rl:*` | Administrado por `express-rate-limit` | Variable | Rate limiting del backend (no se configura aquí) |

**Importante:** Solo los veredictos `malicious` y `benign` se cachean. Los veredictos `unknown` (cuando el modelo ML está caído) **nunca se cachean** — son transitorios y deben reintentarse en el siguiente chequeo.

### Flujo de una Solicitud

```
El usuario visita un dominio
        │
        ▼
  ┌─ ¿Existe verdict:<dominio> en Redis? ──▶ SÍ → Devolver veredicto cacheado (cached: true)
  │     NO (cache miss)
  │     ▼
  ├─ Llamar al modelo ML para clasificación
  │     │
  │     ▼
  ├─ Guardar en PostgreSQL (fn_upsert_domain + fn_save_features)
  │     │
  │     ▼
  ├─ Si veredicto ≠ unknown → Cachear en Redis por 24h
  │     │
  │     ▼
  └─ Registrar evento de chequeo (fn_log_check)
        │
        ▼
    Devolver veredicto al cliente
```

### Invalidación de Caché

Cuando un administrador reclasifica un dominio, el veredicto cacheado se elimina para que la siguiente solicitud obtenga el resultado actualizado:

```js
await db.query('SELECT fn_upsert_domain($1,$2,$3)', [domain, newVerdict, confidence]);
await redis.del(`verdict:${domain}`);
```

---

## Cómo Desplegarlo Localmente

Para levantar este entorno en un equipo de desarrollo:

### Opción 1: Despliegue con Docker Compose (Recomendado)

### 1. Clonar y configurar

```bash
git clone https://github.com/lisettemel/Intelli-db-cache.git
cd Intelli-db-cache/cache
```

Crea un archivo `.env` en el directorio `cache/` con las variables requeridas:

```env
DB_BIND_IP=127.0.0.1        # Usar IP privada de la VM en producción (ej. 10.0.0.5)
REDIS_BIND_IP=127.0.0.1     # Usar IP privada de la VM en producción

DB_NAME=intellidns
DB_USER=intellidns_backend_client
DB_PASSWORD=tuPasswordSegura

REDIS_HOST=127.0.0.1
REDIS_PORT=6379
REDIS_PASSWORD=tuPasswordSeguraDeRedis
```

> **Nunca subas `.env` a git.** Ya está listado en `.gitignore`.

### 2. Levantar los servicios

```bash
docker-compose up -d
```

Esto hará lo siguiente:
- Iniciar **PostgreSQL 16** en el puerto `5432` y crear automáticamente el esquema y las funciones de la base de datos.
- Iniciar **Redis 7** en el puerto `6379` con la configuración endurecida.

### 3. Verificar

```bash
# Verificar que los contenedores estén corriendo
docker ps

# Probar la conexión a PostgreSQL
docker exec -it intellidns_postgres psql -U intellidns_backend_client -d intellidns -c "\dt"

# Probar la conexión a Redis
docker exec -it intellidns_redis redis-cli -a <tu_password_de_redis> PING
# Salida esperada: PONG
```

---

## Otros Archivos Raíz

| Archivo | Descripción |
|---------|-------------|
| `.gitignore` | Excluye archivos `.env` (credenciales reales), `node_modules/`, y el archivo CSV grande de whitelist del control de versiones |

---

## Seguridad de Red

En producción, la VM debe bloquearse con reglas de firewall UFW para que solo el servidor backend pueda alcanzar los puertos de la base de datos y el caché:

```bash
sudo ufw default deny incoming
sudo ufw allow 22/tcp                                                # SSH
sudo ufw allow from <IP_PRIVADA_BACKEND> to any port 5432 proto tcp  # PostgreSQL
sudo ufw allow from <IP_PRIVADA_BACKEND> to any port 6379 proto tcp  # Redis
sudo ufw enable
```

