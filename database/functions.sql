-- ============================================================
-- intelli-dns — Funciones (stored procedures) consumidas por el backend
-- El backend Express las llama con: SELECT * FROM nombre(...);
-- ============================================================


-- ------------------------------------------------------------
-- 1. fn_register_user
-- Registra un anon_id nuevo (instalación de la extensión).
-- Devuelve 'registered' o 'collision' si el anon_id ya existe.
-- El backend usa esto para decirle a la extensión que regenere
-- la frase en el caso (improbable) de colisión.
-- ------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_register_user(p_anon_id CHAR(64))
RETURNS TEXT AS $$
BEGIN
    INSERT INTO users (anon_id) VALUES (p_anon_id);
    RETURN 'registered';
EXCEPTION
    WHEN unique_violation THEN
        RETURN 'collision';
END;
$$ LANGUAGE plpgsql;


-- ------------------------------------------------------------
-- 2. fn_upsert_domain
-- Inserta un dominio nuevo con su veredicto, o lo actualiza si ya
-- existe (reclasificación -> sobrescribe). Devuelve el domain_id.
-- Se llama después de que el ML clasifica en un MISS de caché.
-- ------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_upsert_domain(
    p_domain      TEXT,
    p_verdict     verdict_enum,
    p_confidence  REAL
)
RETURNS BIGINT AS $$
DECLARE
    v_domain_id BIGINT;
BEGIN
    INSERT INTO domains (domain, verdict, confidence, last_classified)
    VALUES (p_domain, p_verdict, p_confidence, now())
    ON CONFLICT (domain) DO UPDATE
        SET verdict         = EXCLUDED.verdict,
            confidence       = EXCLUDED.confidence,
            last_classified  = now()
    RETURNING domain_id INTO v_domain_id;

    RETURN v_domain_id;
END;
$$ LANGUAGE plpgsql;


-- ------------------------------------------------------------
-- 3. fn_save_features
-- Guarda/actualiza las 6 features de un dominio (1-a-1).
-- Se llama junto con fn_upsert_domain tras la clasificación.
-- ------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_save_features(
    p_domain_id    BIGINT,
    p_lex_length   REAL,
    p_lex_entropy  REAL,
    p_lex_digits   REAL,
    p_dns_a_count  INT,
    p_dns_ttl      INT,
    p_dns_age_days INT
)
RETURNS VOID AS $$
BEGIN
    INSERT INTO domain_features (
        domain_id, lex_length, lex_entropy, lex_digits,
        dns_a_count, dns_ttl, dns_age_days
    )
    VALUES (
        p_domain_id, p_lex_length, p_lex_entropy, p_lex_digits,
        p_dns_a_count, p_dns_ttl, p_dns_age_days
    )
    ON CONFLICT (domain_id) DO UPDATE
        SET lex_length   = EXCLUDED.lex_length,
            lex_entropy  = EXCLUDED.lex_entropy,
            lex_digits   = EXCLUDED.lex_digits,
            dns_a_count  = EXCLUDED.dns_a_count,
            dns_ttl      = EXCLUDED.dns_ttl,
            dns_age_days = EXCLUDED.dns_age_days;
END;
$$ LANGUAGE plpgsql;


-- ------------------------------------------------------------
-- 4. fn_log_check
-- Registra un evento de chequeo (una fila por /check).
-- Devuelve el event_id. p_was_cached indica si fue HIT de Redis.
-- ------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_log_check(
    p_anon_id    CHAR(64),
    p_domain_id  BIGINT,
    p_was_cached BOOLEAN
)
RETURNS BIGINT AS $$
DECLARE
    v_event_id BIGINT;
BEGIN
    INSERT INTO check_events (anon_id, domain_id, was_cached)
    VALUES (p_anon_id, p_domain_id, p_was_cached)
    RETURNING event_id INTO v_event_id;

    RETURN v_event_id;
END;
$$ LANGUAGE plpgsql;


-- ------------------------------------------------------------
-- 5. fn_save_report
-- Guarda un reporte de falso positivo/negativo.
-- Señal para revisión futura; NO cambia el veredicto.
-- ------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_save_report(
    p_anon_id      CHAR(64),
    p_domain_id    BIGINT,
    p_report_type  report_enum
)
RETURNS BIGINT AS $$
DECLARE
    v_report_id BIGINT;
BEGIN
    INSERT INTO reports (anon_id, domain_id, report_type)
    VALUES (p_anon_id, p_domain_id, p_report_type)
    RETURNING report_id INTO v_report_id;

    RETURN v_report_id;
END;
$$ LANGUAGE plpgsql;


-- ------------------------------------------------------------
-- 6. fn_stats_me
-- Estadísticas personales de un usuario (endpoint GET /stats/me).
-- Devuelve totales y desglose por veredicto.
-- ------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_stats_me(p_anon_id CHAR(64))
RETURNS TABLE (
    total_checked   BIGINT,
    total_malicious BIGINT,
    total_benign    BIGINT,
    total_unknown   BIGINT,
    since           TIMESTAMPTZ
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        COUNT(*)::BIGINT,
        COUNT(*) FILTER (WHERE d.verdict = 'malicious')::BIGINT,
        COUNT(*) FILTER (WHERE d.verdict = 'benign')::BIGINT,
        COUNT(*) FILTER (WHERE d.verdict = 'unknown')::BIGINT,
        MIN(ce.checked_at)
    FROM check_events ce
    JOIN domains d ON d.domain_id = ce.domain_id
    WHERE ce.anon_id = p_anon_id;
END;
$$ LANGUAGE plpgsql;


-- ------------------------------------------------------------
-- 7. fn_stats_me_history
-- Timeline de detecciones de un usuario (GET /stats/me/history).
-- Paginado con LIMIT/OFFSET.
-- ------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_stats_me_history(
    p_anon_id CHAR(64),
    p_limit   INT,
    p_offset  INT
)
RETURNS TABLE (
    domain      TEXT,
    verdict     verdict_enum,
    confidence  REAL,
    checked_at  TIMESTAMPTZ
) AS $$
BEGIN
    RETURN QUERY
    SELECT d.domain, d.verdict, d.confidence, ce.checked_at
    FROM check_events ce
    JOIN domains d ON d.domain_id = ce.domain_id
    WHERE ce.anon_id = p_anon_id
    ORDER BY ce.checked_at DESC
    LIMIT p_limit OFFSET p_offset;
END;
$$ LANGUAGE plpgsql;


-- ------------------------------------------------------------
-- 8. fn_stats_global
-- Estadísticas globales agregadas (GET /stats/global).
-- El backend cachea el resultado en Redis (~5 min) porque la página
-- es pública y cualquiera puede recargarla.
-- ------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_stats_global()
RETURNS TABLE (
    total_domains    BIGINT,
    total_checks     BIGINT,
    total_malicious  BIGINT,
    total_benign     BIGINT,
    detection_rate   NUMERIC
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        (SELECT COUNT(*) FROM domains)::BIGINT,
        (SELECT COUNT(*) FROM check_events)::BIGINT,
        (SELECT COUNT(*) FROM domains WHERE verdict = 'malicious')::BIGINT,
        (SELECT COUNT(*) FROM domains WHERE verdict = 'benign')::BIGINT,
        ROUND(
            (SELECT COUNT(*) FROM domains WHERE verdict = 'malicious')::NUMERIC
            / NULLIF((SELECT COUNT(*) FROM domains), 0) * 100,
            2
        );
END;
$$ LANGUAGE plpgsql;
