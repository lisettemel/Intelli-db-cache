-- ============================================================
-- intelli-dns — Esquema de base de datos (PostgreSQL)
-- Diseño en 3NF. Solo se almacena el dominio, nunca la URL completa.
-- ============================================================

-- ----- Tipos enumerados -----
-- Los tres estados de veredicto. 'unknown' se usa cuando el ML no
-- estuvo disponible al momento de clasificar.
CREATE TYPE verdict_enum AS ENUM ('malicious', 'benign', 'unknown');

-- Tipos de reporte de feedback del usuario.
CREATE TYPE report_enum AS ENUM ('false_positive', 'false_negative');


-- ----- Tabla: users -----
-- Identidad anónima. anon_id es el hash (SHA-256 -> 64 hex chars)
-- derivado de la frase semilla del lado de la extensión.
-- NO se almacena ningún dato personal por diseño.
CREATE TABLE users (
    anon_id     CHAR(64)    PRIMARY KEY,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);


-- ----- Tabla: domains -----
-- Catálogo de dominios vistos. El veredicto y la confianza dependen
-- SOLO del dominio (no de quién lo consultó), por eso viven aquí y no
-- en check_events -> evita dependencia transitiva (3NF).
-- Un veredicto vigente por dominio: se sobrescribe al reclasificar.
CREATE TABLE domains (
    domain_id        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    domain           TEXT         NOT NULL UNIQUE,
    verdict          verdict_enum NOT NULL,
    confidence       REAL,
    first_seen       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_classified  TIMESTAMPTZ  NOT NULL DEFAULT now()
);


-- ----- Tabla: domain_features -----
-- Las 6 features por dominio (3 léxicas + 3 DNS), relación 1-a-1 con
-- domains. Cada feature es una columna atómica (1NF) -- NO un JSON.
-- Renombrar las columnas a los nombres reales de tus features.
CREATE TABLE domain_features (
    domain_id    BIGINT PRIMARY KEY REFERENCES domains(domain_id) ON DELETE CASCADE,
    lex_length   REAL,   -- ej. longitud del dominio
    lex_entropy  REAL,   -- ej. entropía de Shannon del string
    lex_digits   REAL,   -- ej. proporción de dígitos
    dns_a_count  INT,    -- ej. número de registros A
    dns_ttl      INT,    -- ej. TTL del registro
    dns_age_days INT     -- ej. edad del dominio en días (WHOIS)
);


-- ----- Tabla: check_events -----
-- Bitácora: una fila por cada /check ("guardamos todo").
-- Solo apunta por FK al dominio y al usuario -- NO duplica el veredicto.
CREATE TABLE check_events (
    event_id    BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    anon_id     CHAR(64)    NOT NULL REFERENCES users(anon_id),
    domain_id   BIGINT      NOT NULL REFERENCES domains(domain_id),
    checked_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    was_cached  BOOLEAN     NOT NULL DEFAULT false
);


-- ----- Tabla: reports -----
-- Feedback de falsos positivos/negativos. Señal para revisión humana
-- futura -- NO modifica veredictos automáticamente.
CREATE TABLE reports (
    report_id    BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    anon_id      CHAR(64)    NOT NULL REFERENCES users(anon_id),
    domain_id    BIGINT      NOT NULL REFERENCES domains(domain_id),
    report_type  report_enum NOT NULL,
    reported_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);


-- ----- Índices (rendimiento) -----
-- domains(domain) ya está indexado por la restricción UNIQUE.
CREATE INDEX idx_check_events_anon   ON check_events (anon_id);
CREATE INDEX idx_check_events_time   ON check_events (checked_at);
CREATE INDEX idx_check_events_domain ON check_events (domain_id);
CREATE INDEX idx_reports_domain      ON reports (domain_id);
