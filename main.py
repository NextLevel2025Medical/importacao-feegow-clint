import os
import re
import time
import json
import random
import requests
import psycopg
from datetime import datetime, timedelta, timezone

FEEGOW_BASE = "https://api.feegow.com/v1/api"
CLINT_BASE = "https://api.clint.digital/v1"

FEEGOW_TOKEN = os.environ["FEEGOW_TOKEN"]        # x-access-token
CLINT_TOKEN = os.environ["CLINT_API_TOKEN"]      # api-token
CLINT_ORIGIN_ID = os.environ["CLINT_ORIGIN_ID"]  # fixo
DATABASE_URL = os.environ["DATABASE_URL"]        # postgres

# ---- ajustes finos ----
POLL_OVERLAP_MINUTES = 10     # segurança: revarre últimos 10min (sem duplicar)
RATE_LIMIT_RPS = 3            # limite de req/s (ajuste conforme necessário)
MAX_PROPOSALS_PER_RUN = 200   # evita "rodada infinita" em dia de pico


def now_utc():
    return datetime.now(timezone.utc)

def br_date(d: datetime):
    # Feegow no seu exemplo usa dd-mm-aaaa no querystring
    return d.strftime("%d-%m-%Y")

def normalize_phone(phone: str) -> str:
    if not phone:
        return ""
    digits = re.sub(r"\D+", "", phone)
    # opcional: garantir DDI/DDD, etc.
    return digits

def with_backoff(fn, tries=5, base_delay=0.6, max_delay=8.0):
    for attempt in range(1, tries + 1):
        try:
            return fn()
        except Exception as e:
            if attempt == tries:
                raise
            sleep_for = min(max_delay, base_delay * (2 ** (attempt - 1)))
            sleep_for = sleep_for * (0.8 + random.random() * 0.4)  # jitter
            time.sleep(sleep_for)

class RateLimiter:
    def __init__(self, rps: float):
        self.min_interval = 1.0 / max(rps, 0.1)
        self.last = 0.0

    def wait(self):
        now = time.time()
        delta = now - self.last
        if delta < self.min_interval:
            time.sleep(self.min_interval - delta)
        self.last = time.time()

rl = RateLimiter(RATE_LIMIT_RPS)

def db():
    return psycopg.connect(DATABASE_URL)

def ensure_tables(conn):
    with conn.cursor() as cur:
        cur.execute("""
        create table if not exists clint_deal_ingest (
          proposal_id bigint primary key,
          paciente_id bigint not null,
          proposal_last_update timestamp,
          value numeric,
          created_at timestamp default now(),
          clint_deal_id text,
          status text not null default 'PENDING',
          last_error text,
          attempts int not null default 0
        );
        """)

def feegow_get(path, params=None):
    def _call():
        rl.wait()
        resp = requests.get(
            f"{FEEGOW_BASE}{path}",
            headers={"x-access-token": FEEGOW_TOKEN, "accept": "application/json"},
            params=params,
            timeout=25,
        )
        resp.raise_for_status()
        return resp.json()
    return with_backoff(_call)

def clint_post_deal(payload):
    def _call():
        rl.wait()
        resp = requests.post(
            f"{CLINT_BASE}/deals",
            headers={
                "api-token": CLINT_TOKEN,
                "accept": "application/json",
                "content-type": "application/json",
            },
            data=json.dumps(payload),
            timeout=25,
        )
        resp.raise_for_status()
        return resp.json()
    return with_backoff(_call)

def get_last_watermark(conn):
    # watermark = maior proposal_last_update já processado com sucesso OU pelo menos visto
    with conn.cursor() as cur:
        cur.execute("""
          select coalesce(max(proposal_last_update), '1970-01-01'::timestamp)
          from clint_deal_ingest
        """)
        row = cur.fetchone()
        return row[0]

def upsert_pending(conn, proposal):
    """
    Tenta inserir. Se já existe, retorna False (não é nova).
    Se inseriu agora, retorna True (é nova).
    """
    with conn.cursor() as cur:
        cur.execute("""
          insert into clint_deal_ingest (proposal_id, paciente_id, proposal_last_update, value, status)
          values (%s, %s, %s, %s, 'PENDING')
          on conflict (proposal_id) do nothing
        """, (
            proposal["proposal_id"],
            proposal["PacienteID"],
            proposal.get("proposal_last_update"),
            proposal.get("value"),
        ))
        return cur.rowcount == 1

def mark_done(conn, proposal_id, clint_deal_id=None):
    with conn.cursor() as cur:
        cur.execute("""
          update clint_deal_ingest
             set status='DONE', clint_deal_id=%s, last_error=null
           where proposal_id=%s
        """, (clint_deal_id, proposal_id))

def mark_error(conn, proposal_id, err):
    with conn.cursor() as cur:
        cur.execute("""
          update clint_deal_ingest
             set status='ERROR', last_error=%s, attempts=attempts+1
           where proposal_id=%s
        """, (str(err)[:800], proposal_id))

def fetch_proposals_window():
    # Feegow filtra por data; então pegamos hoje (e opcionalmente ontem se quiser 100% seguro no virar do dia)
    today = now_utc().astimezone().date()
    params = {
        "data_inicio": br_date(datetime.combine(today, datetime.min.time())),
        "data_fim": br_date(datetime.combine(today, datetime.min.time())),
        "tipo_data": "I",
    }
    data = feegow_get("/proposal/list", params=params)
    return data.get("content", []) if data.get("success") else []

def patient_details(paciente_id: int):
    data = feegow_get("/patient/search", params={
        "paciente_id": paciente_id,
        "programa_saude": 1,
        "photo": 0
    })
    if not data.get("success"):
        raise RuntimeError(f"Feegow patient/search falhou p/ {paciente_id}")
    return data["content"]

def build_clint_payload(proposal, patient):
    name = patient.get("nome") or "SEM NOME"
    celulares = patient.get("celulares") or []
    phone = normalize_phone(celulares[0] if celulares else "")
    value = proposal.get("value") or 0

    # Dica: embutir o proposal_id no nome ajuda MUITO a rastrear
    deal_name = f"{name} - Proposta #{proposal['proposal_id']}"

    return {
        "origin_id": CLINT_ORIGIN_ID,
        "name": deal_name,
        "phone": phone,
        "value": float(value)
    }

def main():
    with db() as conn:
        conn.autocommit = False

        ensure_tables(conn)
        conn.commit()

        watermark = get_last_watermark(conn)
        cutoff = (now_utc().replace(tzinfo=None) - timedelta(minutes=POLL_OVERLAP_MINUTES))

        proposals = fetch_proposals_window()

        # filtra pelo "last_update" quando existir, senão processa (idempotência segura)
        def parse_last_update(p):
            s = p.get("proposal_last_update")
            if not s:
                return None
            # exemplo: "2026-02-02 13:41:45"
            return datetime.strptime(s, "%Y-%m-%d %H:%M:%S")

        candidates = proposals

        candidates = sorted(candidates, key=lambda x: x.get("proposal_id", 0))[:MAX_PROPOSALS_PER_RUN]

        created = 0
        skipped = 0
        errors = 0

        for p in candidates:
            try:
                is_new = upsert_pending(conn, p)
                if not is_new:
                    skipped += 1
                    continue

                patient = patient_details(int(p["PacienteID"]))
                payload = build_clint_payload(p, patient)
                res = clint_post_deal(payload)

                # se a API do Clint devolver um id, capture aqui:
                clint_id = res.get("id") or res.get("deal_id")
                mark_done(conn, int(p["proposal_id"]), clint_id)
                conn.commit()
                created += 1

            except Exception as e:
                conn.rollback()
                try:
                    # registra erro no banco
                    with conn.cursor() as cur:
                        # garante que a linha exista (caso falhou antes de inserir)
                        cur.execute("""
                          insert into clint_deal_ingest (proposal_id, paciente_id, status, last_error, attempts)
                          values (%s, %s, 'ERROR', %s, 1)
                          on conflict (proposal_id)
                          do update set status='ERROR', last_error=%s, attempts=clint_deal_ingest.attempts+1
                        """, (
                            int(p.get("proposal_id", 0)),
                            int(p.get("PacienteID", 0)),
                            str(e)[:800],
                            str(e)[:800],
                        ))
                    conn.commit()
                except:
                    conn.rollback()
                errors += 1

        print(json.dumps({
            "run_at": now_utc().isoformat(),
            "candidates": len(candidates),
            "created": created,
            "skipped_existing": skipped,
            "errors": errors
        }, ensure_ascii=False))

if __name__ == "__main__":
    main()
