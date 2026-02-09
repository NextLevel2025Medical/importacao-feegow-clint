from __future__ import annotations

from datetime import datetime, date, time, timedelta, timezone
from zoneinfo import ZoneInfo
from typing import Optional, Dict, Any
from types import SimpleNamespace

from fastapi import FastAPI, Depends, Request, Form, Query
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from sqlmodel import Session, select, delete
from sqlalchemy import or_, text, func
from sqlalchemy.exc import IntegrityError
from urllib.parse import quote

from db import create_db_and_tables, get_session, engine
from models import User, Room, Reservation, ReservationRequest, AuditLog, SurgicalMapEntry, AgendaBlock, AgendaBlockSurgeon, GustavoAgendaSnapshot, LodgingReservation
from auth import hash_password, verify_password, require

from pathlib import Path

import calendar
import os
import json
import logging
from logging.handlers import RotatingFileHandler

import threading
import time as pytime

TZ = timezone(timedelta(hours=-3))  # Brasil (-03:00)
SLOT_MINUTES = 30
START_HOUR = 7
END_HOUR = 19  # 19:00 (último slot começa 18:30)

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key="CHANGE_ME_SUPER_SECRET_KEY")
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

AUDIT_LOG_PATH = os.getenv("AUDIT_LOG_PATH", "audit.log")

audit_logger = logging.getLogger("audit")
audit_logger.setLevel(logging.INFO)
audit_logger.propagate = False

if not audit_logger.handlers:
    fh = RotatingFileHandler(
        AUDIT_LOG_PATH,
        maxBytes=2_000_000,
        backupCount=5,
        encoding="utf-8",
    )
    fh.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
    audit_logger.addHandler(fh)

def to_db_dt(dt: datetime) -> datetime:
    """Converte qualquer datetime para horário local (-03) e remove tz/segundos p/ persistir no SQLite."""
    if dt.tzinfo is not None:
        dt = dt.astimezone(TZ).replace(tzinfo=None)
    return dt.replace(second=0, microsecond=0)

def fmt_brasilia(dt: datetime | None) -> str:
    if not dt:
        return "—"
    # Se veio "naive" do SQLite, vamos assumir que era UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(TZ).strftime("%d/%m/%Y %H:%M")

def slot_keys(dt: datetime) -> tuple[str, str]:
    """Retorna 2 chaves: sem segundos e com segundos, para evitar mismatch com o front."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=TZ)
    dt = dt.replace(second=0, microsecond=0)
    return (
        dt.isoformat(timespec="minutes"),  # 2025-11-29T07:00-03:00
        dt.isoformat(timespec="seconds"),  # 2025-11-29T07:00:00-03:00
    )

def local_today_str() -> str:
    return datetime.now(TZ).date().isoformat()


def safe_selected_and_day(raw_date: Optional[str]) -> tuple[str, date]:
    """
    Aceita None, "" ou uma string iso (YYYY-MM-DD).
    Retorna (selected_str, day_date) sempre válido, sem estourar ValueError.
    """
    selected = (raw_date or "").strip() or local_today_str()
    try:
        day = datetime.fromisoformat(selected).date()
    except ValueError:
        selected = local_today_str()
        day = datetime.fromisoformat(selected).date()
    return selected, day

def safe_selected_month(raw: Optional[str]) -> tuple[str, date, date, list[date]]:
    """
    Aceita None, "" ou 'YYYY-MM'. Retorna:
    selected ('YYYY-MM'), first_day, next_month_first_day, list_days
    """
    selected = (raw or "").strip() or datetime.now(TZ).strftime("%Y-%m")
    try:
        dt = datetime.strptime(selected, "%Y-%m")
    except ValueError:
        selected = datetime.now(TZ).strftime("%Y-%m")
        dt = datetime.strptime(selected, "%Y-%m")

    first = date(dt.year, dt.month, 1)
    # primeiro dia do mês seguinte
    if dt.month == 12:
        next_first = date(dt.year + 1, 1, 1)
    else:
        next_first = date(dt.year, dt.month + 1, 1)

    last_day = calendar.monthrange(dt.year, dt.month)[1]
    days = [date(dt.year, dt.month, d) for d in range(1, last_day + 1)]
    return selected, first, next_first, days

def build_slots_for_day(day: date):
    start_dt = datetime.combine(day, time(START_HOUR, 0), tzinfo=TZ)
    end_dt = datetime.combine(day, time(END_HOUR, 0), tzinfo=TZ)
    slots = []
    cur = start_dt
    while cur < end_dt:
        slots.append(cur)
        cur += timedelta(minutes=SLOT_MINUTES)
    return slots


def get_current_user(request: Request, session: Session) -> Optional[User]:
    uid = request.session.get("user_id")
    if not uid:
        return None
    return session.get(User, uid)

def audit_event(
    request: Request,
    actor: Optional[User],
    action: str,
    *,
    success: bool = True,
    message: Optional[str] = None,
    room_id: Optional[int] = None,
    target_type: Optional[str] = None,
    target_id: Optional[int] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    extra: Optional[dict] = None,
):
    ip = request.client.host if request.client else None
    ua = request.headers.get("user-agent")
    method = request.method
    path = request.url.path

    # 1) grava no arquivo (nunca pode quebrar o sistema)
    try:
        payload = {
            "actor": getattr(actor, "username", None),
            "role": getattr(actor, "role", None),
            "action": action,
            "success": success,
            "message": message,
            "room_id": room_id,
            "target_type": target_type,
            "target_id": target_id,
            "start_time": start_time.isoformat(timespec="minutes") if start_time else None,
            "end_time": end_time.isoformat(timespec="minutes") if end_time else None,
            "ip": ip,
            "path": path,
            "method": method,
            "extra": extra or None,
        }
        audit_logger.info(json.dumps(payload, ensure_ascii=False))
    except Exception:
        pass

    # 2) grava no banco (isolado, pra não atrapalhar transações do request)
    try:
        with Session(engine) as s:
            row = AuditLog(
                actor_user_id=getattr(actor, "id", None),
                actor_username=getattr(actor, "username", None),
                actor_role=getattr(actor, "role", None),
                action=action,
                success=success,
                message=message,
                room_id=room_id,
                target_type=target_type,
                target_id=target_id,
                start_time=start_time,
                end_time=end_time,
                ip=ip,
                user_agent=ua,
                path=path,
                method=method,
                extra_json=json.dumps(extra, ensure_ascii=False) if extra else None,
            )
            s.add(row)
            s.commit()
    except Exception as e:
        audit_logger.exception("AUDIT_DB_FAIL | action=%s | err=%s", action, str(e))


def redirect(path: str):
    return RedirectResponse(path, status_code=303)


def seed_if_empty(session: Session):
    # =========================
    # USERS (cria SE não existir)
    # =========================
    def ensure_user(username: str, full_name: str, role: str, password: str):
        existing = session.exec(select(User).where(User.username == username)).first()
        if not existing:
            session.add(
                User(
                    username=username,
                    full_name=full_name,
                    role=role,
                    password_hash=hash_password(password),
                    is_active=True,
                )
            )

    # Admin padrão
    ensure_user("secretaria", "Secretaria (Admin)", "admin", "admin123")

    # Médicos padrão
    doctors = [
        ("drgustavo", "Dr. Gustavo Aquino"),
        ("drricardo", "Dr. Ricardo Vilela"),
        ("draalice", "Dra. Alice Osório"),
        ("dramelina", "Dra. Mellina Tanure"),
        ("dravanessa", "Dra. Vanessa Santos"),
        ("drathamilys", "Dra. Thamilys Benfica"),
        ("drastela", "Dra. Stela Temponi"),
        ("draglesiane", "Dra. Glesiane Teixeira"),
    ]
    for username, name in doctors:
        ensure_user(username, name, "doctor", "senha123")

    # NOVO: usuário do Mapa Cirúrgico
    ensure_user("johnny.ge", "Johnny", "surgery", "@Ynnhoj91")
    ensure_user("ana.maria", "Ana Maria", "surgery", "AnaM#2025@91")
    ensure_user("cris.galdino", "Cristiane Galdino", "surgery", "CrisG@2025#47")
    ensure_user("carolina.abdo", "Carolina", "surgery", "Caro!2025#38")
    ensure_user("ariella.vieira", "Ariella", "surgery", "Ariella$2026")
    ensure_user("camilla.martins", "Camilla", "comissao", "Camilla*2026")
    ensure_user("sayonara.goncalves", "Sayonara", "surgery", "Sayonara*2026")

    session.commit()

    # =========================
    # ROOMS (cria SE não existir)
    # =========================
    rooms = session.exec(select(Room)).all()
    if not rooms:
        default_rooms = [
            Room(name="Consultório 1", is_active=True),
            Room(name="Consultório 2", is_active=True),
            Room(name="Consultório 3", is_active=True),
        ]
        session.add_all(default_rooms)
        session.commit()

def validate_mapa_rules(
    session: Session,
    day: date,
    surgeon_id: int,
    procedure_type: str,
    uses_hsr: bool = False,
    exclude_entry_id: int | None = None,
) -> str | None:
    """
    Regras do Mapa Cirúrgico

    ✅ Reserva conta como agendamento (SurgicalMapEntry com is_pre_reservation=True também entra na contagem).

    Regras:
    - Dr. Gustavo Aquino:
        * Cirurgia / Procedimento Simples: somente Segunda e Quarta (máx 2 por dia)
        * Refinamento: Segunda e Quarta (máx 2 por dia) + Sexta (máx 1 por dia)
    - Dra. Alice Osório e Dr. Ricardo Vilela:
        * Operam Terça, Quinta e Sexta (máx 1 por dia)
        * Não podem operar no mesmo dia (se um tem qualquer agendamento/reserva, o outro não pode)
    - Slot HSR: proibido em Janeiro e Julho
    """

    gustavo = session.exec(select(User).where(User.full_name == "Dr. Gustavo Aquino")).first()
    alice = session.exec(select(User).where(User.full_name == "Dra. Alice Osório")).first()
    ricardo = session.exec(select(User).where(User.full_name == "Dr. Ricardo Vilela")).first()

    def _apply_exclude(q):
        if exclude_entry_id is not None:
            return q.where(SurgicalMapEntry.id != exclude_entry_id)
        return q

    # HSR jan/jul
    if uses_hsr and day.month in (1, 7):
        return "Regra: não é permitido agendar Slot HSR em Janeiro e Julho."

    wd = day.weekday()  # 0=Seg,1=Ter,2=Qua,3=Qui,4=Sex,5=Sáb,6=Dom

    # =========================
    # (A) Dr. Gustavo Aquino
    # =========================
    if gustavo and surgeon_id == gustavo.id:
        if procedure_type == "Refinamento":
            # Seg/Qua até 2, Sex até 1
            if wd in (0, 2):
                cap = 2
            elif wd == 4:
                cap = 1
            else:
                return "Regra: Dr. Gustavo Aquino opera Refinamento apenas na Segunda, Quarta ou Sexta."
        else:
            # Cirurgia / Procedimento Simples: só Seg/Qua até 2
            if wd not in (0, 2):
                return "Regra: Dr. Gustavo Aquino opera Cirurgia/Procedimento Simples apenas na Segunda e Quarta."
            cap = 2

        q = select(SurgicalMapEntry.id).where(
            SurgicalMapEntry.day == day,
            SurgicalMapEntry.surgeon_id == gustavo.id,
        )
        q = _apply_exclude(q)
        already = session.exec(q).all()

        if len(already) >= cap:
            if cap == 2:
                return "Regra: Dr. Gustavo Aquino não pode ter mais de 2 agendamentos no mesmo dia."
            return "Regra: Dr. Gustavo Aquino não pode ter mais de 1 agendamento (Refinamento) na Sexta-feira."

        return None

    # =========================
    # (B) Alice e Ricardo
    # =========================
    if alice and ricardo and surgeon_id in (alice.id, ricardo.id):
        # dias permitidos: Ter/Qui/Sex
        if wd not in (1, 3, 4):
            return "Regra: Dra. Alice Osório e Dr. Ricardo Vilela operam apenas na Terça, Quinta ou Sexta."

        # capacidade do próprio médico: 1 por dia
        q_self = select(SurgicalMapEntry.id).where(
            SurgicalMapEntry.day == day,
            SurgicalMapEntry.surgeon_id == surgeon_id,
        )
        q_self = _apply_exclude(q_self)
        if session.exec(q_self).first():
            return "Regra: Dra. Alice Osório e Dr. Ricardo Vilela não podem ter mais de 1 procedimento no mesmo dia."

        # conflito Alice x Ricardo: se o outro tem qualquer agendamento/reserva no dia, bloqueia
        other_id = ricardo.id if surgeon_id == alice.id else alice.id
        q_other = select(SurgicalMapEntry.id).where(
            SurgicalMapEntry.day == day,
            SurgicalMapEntry.surgeon_id == other_id,
        )
        q_other = _apply_exclude(q_other)
        if session.exec(q_other).first():
            return "Regra: Dra. Alice Osório e Dr. Ricardo Vilela não podem operar no mesmo dia."

        return None

    # Outros cirurgiões (se existirem) sem regras específicas aqui
    return None

# ============================================================
# HOSPEDAGEM (2 suítes + 1 apartamento) - reservas por período
# check_out é NÃO inclusivo (data de saída)
# ============================================================

def validate_lodging_period(check_in: date, check_out: date) -> Optional[str]:
    if not check_in or not check_out:
        return "Informe check-in e check-out."
    if check_out <= check_in:
        return "Período inválido: check-out deve ser após check-in."
    return None


def validate_lodging_conflict(
    session: Session,
    unit: str,
    check_in: date,
    check_out: date,
    exclude_id: Optional[int] = None,
) -> Optional[str]:
    # conflito se: novo_in < existente_out AND novo_out > existente_in
    q = select(LodgingReservation).where(
        LodgingReservation.unit == unit,
        LodgingReservation.check_in < check_out,
        LodgingReservation.check_out > check_in,
    )
    if exclude_id is not None:
        q = q.where(LodgingReservation.id != exclude_id)

    exists = session.exec(q).first()
    if exists:
        audit_logger.info(
            "LODGE_CONFLICT: new_unit=%s new_ci=%s new_co=%s | "
            "found_id=%s found_unit=%s found_ci=%s found_co=%s found_patient=%s pre=%s surgery_entry_id=%s",
            unit, check_in, check_out,
            getattr(exists, "id", None),
            getattr(exists, "unit", None),
            getattr(exists, "check_in", None),
            getattr(exists, "check_out", None),
            getattr(exists, "patient_name", None),
            getattr(exists, "is_pre_reservation", None),
            getattr(exists, "surgery_entry_id", None),
        )
        return "Hospedagem indisponível: já existe reserva nesse período para esta acomodação."
    return None

def get_lodging_conflict_row(
    session: Session,
    unit: str,
    check_in: date,
    check_out: date,
    exclude_id: Optional[int] = None,
):
    q = select(LodgingReservation).where(
        LodgingReservation.unit == unit,
        LodgingReservation.check_in < check_out,
        LodgingReservation.check_out > check_in,
    )
    if exclude_id is not None:
        q = q.where(LodgingReservation.id != exclude_id)

    return session.exec(q).first()

def human_unit(unit: str) -> str:
    return {
        "suite_1": "Suíte 1",
        "suite_2": "Suíte 2",
        "apto": "Apartamento",
    }.get(unit, unit)

def _weekday_pt(idx: int) -> str:
    names = ["Segunda", "Terça", "Quarta", "Quinta", "Sexta", "Sábado", "Domingo"]
    return names[idx]

# ============================
# RELATÓRIO DR. GUSTAVO (snapshot diário às 19h)
# ============================

GUSTAVO_REPORT_CFG_PATH = (Path(__file__).resolve().parent / "gustavo_report_config.json")

# OVERRIDES (override vence tudo) - por dia e por médico
GUSTAVO_REPORT_OVERRIDES_PATH = (Path(__file__).resolve().parent / "gustavo_report_overrides.json")

# Ordem fixa (hierarquia/faturamento) — NÃO MUDAR
GUSTAVO_REPORT_SURGEONS = [
    ("drgustavo", "Gustavo"),
    ("drricardo", "Ricardo"),
    ("draalice", "Alice"),
    ("dramelina", "Melina"),
    ("drathamilys", "Thamilys"),
    ("dravanessa", "Vanessa"),
]

# Emojis permitidos (no relatório)
REPORT_EMOJIS = {"🟢", "🟡", "🔴", "🔵", "⚫️"}

def load_gustavo_overrides() -> dict:
    """
    Estrutura:
    {
      "YYYY-MM-DD": {
        "drgustavo": {"emoji": "🟢", "reason": "texto", "by": "johnny.ge", "at": "iso"},
        ...
      }
    }
    """
    try:
        if not GUSTAVO_REPORT_OVERRIDES_PATH.exists():
            return {}
        raw = json.loads(GUSTAVO_REPORT_OVERRIDES_PATH.read_text(encoding="utf-8") or "{}")
        return raw if isinstance(raw, dict) else {}
    except Exception:
        return {}

def save_gustavo_overrides(data: dict) -> None:
    GUSTAVO_REPORT_OVERRIDES_PATH.write_text(
        json.dumps(data, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

def _default_gustavo_month_keys(snapshot_day_sp: date) -> list[str]:
    y0, m0 = snapshot_day_sp.year, snapshot_day_sp.month
    y1, m1 = _add_months(y0, m0, 1)
    y2, m2 = _add_months(y0, m0, 2)
    return [f"{y0:04d}-{m0:02d}", f"{y1:04d}-{m1:02d}", f"{y2:04d}-{m2:02d}"]

def load_gustavo_selected_month_keys(snapshot_day_sp: date) -> list[str]:
    try:
        if not GUSTAVO_REPORT_CFG_PATH.exists():
            return _default_gustavo_month_keys(snapshot_day_sp)
        data = json.loads(GUSTAVO_REPORT_CFG_PATH.read_text(encoding="utf-8") or "{}")
        keys = data.get("selected_months", [])
        if not isinstance(keys, list) or not keys:
            return _default_gustavo_month_keys(snapshot_day_sp)
        # filtra apenas strings tipo YYYY-MM
        ok = []
        for k in keys:
            if isinstance(k, str) and len(k) == 7 and k[4] == "-":
                ok.append(k)
        return ok or _default_gustavo_month_keys(snapshot_day_sp)
    except Exception:
        return _default_gustavo_month_keys(snapshot_day_sp)

def save_gustavo_selected_month_keys(keys: list[str]) -> None:
    payload = {"selected_months": keys, "updated_at": datetime.utcnow().isoformat()}
    GUSTAVO_REPORT_CFG_PATH.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

def _keys_to_month_tuples(keys: list[str]) -> list[tuple[int, int]]:
    months: list[tuple[int, int]] = []
    for k in keys:
        try:
            yy, mm = k.split("-")
            y = int(yy)
            m = int(mm)
            if 1 <= m <= 12:
                months.append((y, m))
        except Exception:
            continue
    # ordena e remove duplicados mantendo ordem
    seen = set()
    out = []
    for ym in sorted(months):
        if ym not in seen:
            seen.add(ym)
            out.append(ym)
    return out

PT_MONTHS = [
    "janeiro", "fevereiro", "março", "abril", "maio", "junho",
    "julho", "agosto", "setembro", "outubro", "novembro", "dezembro"
]
DOW_ABBR = ["Seg", "Ter", "Qua", "Qui", "Sex", "Sáb", "Dom"]

def _add_months(year: int, month: int, delta: int) -> tuple[int, int]:
    """Soma delta meses em (year, month). Retorna (new_year, new_month)."""
    m = month + delta
    y = year + (m - 1) // 12
    m = (m - 1) % 12 + 1
    return y, m

def _month_start(year: int, month: int) -> date:
    return date(year, month, 1)

def _month_end(year: int, month: int) -> date:
    import calendar as _cal
    last_day = _cal.monthrange(year, month)[1]
    return date(year, month, last_day)

def _month_label_pt(year: int, month: int) -> str:
    # você pode escolher title() no display
    return PT_MONTHS[month-1].upper()

def _proc_bucket(procedure_type: str | None) -> str:
    """
    Retorna 'cir' | 'ref' | 'simp' baseado no texto.
    - Cirurgia: 'cirurgia'
    - Refinamento: contém 'ref'
    - Procedimento simples: contém 'simp' ou 'proced'
    """
    if not procedure_type:
        return "cir"
    pt = procedure_type.strip().lower()
    if pt == "cirurgia":
        return "cir"
    if "ref" in pt:
        return "ref"
    if "simp" in pt or "proced" in pt:
        return "simp"
    return "cir"

def build_gustavo_whatsapp_messages(
    session: Session,
    snapshot_day_sp: date,
    month_keys: list[str] | None = None,
) -> tuple[str, str, dict]:
    """
    Gera as duas mensagens (Panorama + Detalhe)

    Regras:
    - meses: vêm da configuração (seleção) ou default (mês atual + 2)
    - aparecem SOMENTE Segunda (0) e Quarta (2)
    - Emojis: ✅ cheio | 🟡 parcial | 🔴 livre | 🔵 bloqueio/recesso
    - Sem descrições extras (apenas as bolinhas)
    - Sem linhas em branco entre dias do mesmo mês (apenas entre meses)
    """

    gustavo = session.exec(select(User).where(User.username == "drgustavo")).first()
    if not gustavo:
        raise RuntimeError("Usuário drgustavo não encontrado no banco.")

    # 1) resolve meses a usar
    if month_keys is None:
        month_keys = load_gustavo_selected_month_keys(snapshot_day_sp)
    months = _keys_to_month_tuples(month_keys)
    if not months:
        months = _keys_to_month_tuples(_default_gustavo_month_keys(snapshot_day_sp))

    months_titles = " • ".join(
        f"{PT_MONTHS[mm-1].title()}/{str(yy)[2:]}" for (yy, mm) in months
    )

    period_start = _month_start(months[0][0], months[0][1])
    period_end = _month_end(months[-1][0], months[-1][1])

    # --- coleta dados para o relatório (6 médicos) ---
    # carrega usuários
    surgeons_map: dict[str, User] = {}
    for (uname, _lbl) in GUSTAVO_REPORT_SURGEONS:
        u = session.exec(select(User).where(User.username == uname)).first()
        if u:
            surgeons_map[uname] = u

    surgeon_ids = [u.id for u in surgeons_map.values() if u.id is not None]

    # pega todos os agendamentos no período (somente dos 6 médicos)
    all_entries = []
    if surgeon_ids:
        all_entries = session.exec(
            select(SurgicalMapEntry).where(
                SurgicalMapEntry.day >= period_start,
                SurgicalMapEntry.day <= period_end,
                SurgicalMapEntry.surgeon_id.in_(surgeon_ids),
            )
        ).all()

    # organiza por dia e por username (NÃO contar pre-reservation)
    entries_by_day_user: dict[date, dict[str, list[SurgicalMapEntry]]] = {}
    month_real_counts: dict[tuple[int, int], dict[str, int]] = {}

    id_to_username = {u.id: uname for (uname, _lbl) in GUSTAVO_REPORT_SURGEONS for u in [surgeons_map.get(uname)] if u}

    for e in all_entries:
        if getattr(e, "is_pre_reservation", False):
            continue
        if not getattr(e, "day", None) or not getattr(e, "surgeon_id", None):
            continue

        uname = id_to_username.get(e.surgeon_id)
        if not uname:
            continue

        entries_by_day_user.setdefault(e.day, {}).setdefault(uname, []).append(e)

        ym = (e.day.year, e.day.month)
        month_real_counts.setdefault(ym, {})
        month_real_counts[ym][uname] = month_real_counts[ym].get(uname, 0) + 1

    # overrides (vence tudo)
    overrides = load_gustavo_overrides()

    pano_lines: list[str] = [
        "RELATÓRIO – VISÃO GERAL (AGENDA CIRÚRGICA)",
        f"📅 {months_titles}",
        ""
    ]


    detail_parts: list[str] = []
    months_payload = []

    for (yy, mm) in months:
        m_start = _month_start(yy, mm)
        m_end = _month_end(yy, mm)

        # Cabeçalho do mês
        detail_parts.append(f"*{_month_label_pt(yy, mm)} – VISÃO GERAL*")
        detail_parts.append("Legenda: Gustavo-Ricardo-Alice-Melina-Thamilys-Vanessa")

        # mês “todo azul” por médico se não teve NENHUM agendamento real no mês
        month_counts = month_real_counts.get((yy, mm), {})
        month_all_blue = {u: (month_counts.get(u, 0) == 0) for (u, _lbl) in GUSTAVO_REPORT_SURGEONS}

        lines: list[str] = []

        d = m_start
        while d <= m_end:
            dow = d.weekday()  # 0=Seg ... 5=Sáb ... 6=Dom

            # mostra Seg-Sex sempre
            show_day = dow in (0, 1, 2, 3, 4)

            # Sábado só aparece se houver agendamento real no sistema (qualquer um dos 6)
            if dow == 5:
                any_real_sat = False
                day_bucket = entries_by_day_user.get(d, {})
                for (uname, _lbl) in GUSTAVO_REPORT_SURGEONS:
                    if len(day_bucket.get(uname, [])) > 0:
                        any_real_sat = True
                        break
                show_day = any_real_sat

            # Domingo nunca
            if dow == 6:
                show_day = False

            if not show_day:
                d += timedelta(days=1)
                continue

            day_bucket = entries_by_day_user.get(d, {})
            day_over = (overrides.get(d.isoformat()) or {})

            # atalhos p/ Ricardo x Alice
            ric_real = len(day_bucket.get("drricardo", []))
            ali_real = len(day_bucket.get("draalice", []))

            emojis_line: list[str] = []

            for (uname, _lbl) in GUSTAVO_REPORT_SURGEONS:
                # override vence tudo
                if uname in day_over:
                    ov_emoji = (day_over[uname] or {}).get("emoji")
                    if isinstance(ov_emoji, str) and ov_emoji in REPORT_EMOJIS:
                        emojis_line.append(ov_emoji)
                        continue

                # mês inteiro azul se não operou nada
                if uname == "drgustavo" and month_all_blue.get(uname, False):
                    emojis_line.append("🔵")
                    continue

                uobj = surgeons_map.get(uname)
                if not uobj:
                    emojis_line.append("🔴")
                    continue

                # bloqueio por agenda (azul)
                if validate_mapa_block_rules(session, d, uobj.id):
                    emojis_line.append("🔵")
                    continue

                real_cnt = len(day_bucket.get(uname, []))

                # -------------------------
                # REGRAS POR MÉDICO
                # -------------------------

                # GUSTAVO
                if uname == "drgustavo":
                    if dow in (0, 2):  # Seg/Qua
                        if real_cnt >= 2:
                            emojis_line.append("🟢")
                        elif real_cnt == 1:
                            emojis_line.append("🟡")
                        else:
                            emojis_line.append("🔴")
                    elif dow in (1, 3):  # Ter/Qui (auxilia) => default preto
                        emojis_line.append("🟢" if real_cnt >= 1 else "⚫️")
                    elif dow == 4:  # Sex (refino) => default preto; se tiver agendamento => verde
                        emojis_line.append("🟢" if real_cnt >= 1 else "⚫️")
                    else:
                        # Sábado (se apareceu) entra na lógica “sem destaques”: aberto
                        emojis_line.append("🟢" if real_cnt >= 1 else "🔴")
                    continue

                # RICARDO / ALICE
                if uname in ("drricardo", "draalice"):

                    # SEGUNDA E QUARTA → AUXILIAM GUSTAVO
                    if dow in (0, 2):
                        # default preto, verde apenas se houver agendamento próprio
                        emojis_line.append("🟢" if real_cnt >= 1 else "⚫️")

                    # TERÇA, QUINTA E SEXTA → OPERÁVEIS COM EXCLUSIVIDADE
                    elif dow in (1, 3, 4):
                        if uname == "drricardo":
                            if ric_real > 0:
                                emojis_line.append("🟢")
                            elif ali_real > 0:
                                emojis_line.append("⚫️")
                            else:
                                emojis_line.append("🔴")
                        else:  # draalice
                            if ali_real > 0:
                                emojis_line.append("🟢")
                            elif ric_real > 0:
                                emojis_line.append("⚫️")
                            else:
                                emojis_line.append("🔴")

                    # SÁBADO → PRETO, VERDE SE HOUVER AGENDAMENTO
                    elif dow == 5:
                        emojis_line.append("🟢" if real_cnt >= 1 else "⚫️")

                    else:
                        emojis_line.append("🔴")

                    continue

                # THAMILYS
                if uname == "drathamilys":

                    # SEG / QUA → AUXILIA GUSTAVO
                    if dow in (0, 2):
                        emojis_line.append("🟢" if real_cnt >= 1 else "⚫️")

                    # TERÇA → SEMPRE PRETO
                    elif dow == 1:
                        emojis_line.append("⚫️")

                    # QUINTA E SEXTA → OPERÁVEL
                    elif dow in (3, 4):
                        emojis_line.append("🟢" if real_cnt >= 1 else "🔴")

                    # SÁBADO
                    elif dow == 5:
                        emojis_line.append("🟢" if real_cnt >= 1 else "⚫️")

                    else:
                        emojis_line.append("🔴")

                    continue

                # MELLINA
                if uname in ("dramelina","dravanessa"):

                    # SEG / QUA → AUXILIA GUSTAVO
                    if dow in (0, 2):
                        emojis_line.append("🟢" if real_cnt >= 1 else "⚫️")

                    # TER / QUI / SEX → OPERÁVEL
                    elif dow in (1, 3, 4):
                        emojis_line.append("🟢" if real_cnt >= 1 else "🔴")

                    # SÁBADO
                    elif dow == 5:
                        emojis_line.append("🟢" if real_cnt >= 1 else "⚫️")

                    else:
                        emojis_line.append("🔴")

                    continue


            lines.append(f"{DOW_ABBR[dow]} {d.strftime('%d/%m')}  {''.join(emojis_line)}")
            d += timedelta(days=1)

        detail_parts.extend(lines)

        # separador SOMENTE entre meses (uma linha em branco)
        detail_parts.append("")

    message_1 = "\n".join(detail_parts).strip()
    message_2 = ""

    payload = {
        "doctor_username": "drgustavo",
        "snapshot_day_sp": snapshot_day_sp.isoformat(),
        "period_start": period_start.isoformat(),
        "period_end": period_end.isoformat(),
    }

    return message_1, message_2, payload

def _whatsapp_send(message_1: str, message_2: str) -> None:
    """
    Disparo via API (opcional).
    Só envia se WHATSAPP_API_URL / WHATSAPP_API_TOKEN / WHATSAPP_TO estiverem configuradas.
    """
    import requests

    url = os.getenv("WHATSAPP_API_URL", "").strip()
    token = os.getenv("WHATSAPP_API_TOKEN", "").strip()
    to = os.getenv("WHATSAPP_TO", "").strip()

    if not url or not token or not to:
        audit_logger.info("WHATSAPP: envio ignorado (WHATSAPP_API_URL/TOKEN/TO não configurados).")
        return

    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    # Ajuste conforme seu provedor (BotConversa/Twilio/etc.)
    payload = {"to": to, "messages": [message_1, message_2]}

    try:
        r = requests.post(url, headers=headers, json=payload, timeout=30)
        audit_logger.info(f"WHATSAPP: status={r.status_code} body={r.text[:200]}")
    except Exception as e:
        audit_logger.exception(f"WHATSAPP: erro ao enviar: {e}")

def save_gustavo_snapshot_and_send(session: Session, snapshot_day_sp: date) -> GustavoAgendaSnapshot:
    """Gera e salva snapshot do dia (idempotente por snapshot_date)."""

    existing = session.exec(
        select(GustavoAgendaSnapshot).where(GustavoAgendaSnapshot.snapshot_date == snapshot_day_sp)
    ).first()
    if existing:
        return existing

    msg1, msg2, payload = build_gustavo_whatsapp_messages(session, snapshot_day_sp, month_keys=None)

    snap = GustavoAgendaSnapshot(
        snapshot_date=snapshot_day_sp,
        generated_at=datetime.utcnow(),
        period_start=date.fromisoformat(payload["period_start"]),
        period_end=date.fromisoformat(payload["period_end"]),
        message_1=msg1,
        message_2=msg2,
        payload=payload,
    )

    session.add(snap)
    try:
        session.commit()
    except IntegrityError:
        # idempotência em ambientes com +1 worker (Render/Uvicorn)
        session.rollback()
        existing = session.exec(
            select(GustavoAgendaSnapshot).where(GustavoAgendaSnapshot.snapshot_date == snapshot_day_sp)
        ).first()
        if existing:
            return existing
        raise

    session.refresh(snap)

    # dispara WhatsApp usando o texto salvo
    _whatsapp_send(msg1, msg2)

    return snap

def _next_run_19h_sp(now_sp: datetime) -> datetime:
    run_today = now_sp.replace(hour=19, minute=0, second=0, microsecond=0)
    if now_sp < run_today:
        return run_today
    return run_today + timedelta(days=1)

def start_gustavo_snapshot_scheduler() -> None:
    """
    Scheduler simples (thread)
    - roda diariamente às 19h (horário SP)
    - fallback (Opção A): ao subir, se já passou de 19h e ainda não existe snapshot de hoje, gera imediatamente
    """

    def runner():
        while True:
            now_sp = datetime.now(TZ)
            today_sp = now_sp.date()

            # fallback: se já passou de 19h e não existe snapshot hoje, gera agora
            if now_sp.hour >= 19:
                with Session(engine) as session:
                    exists = session.exec(
                        select(GustavoAgendaSnapshot).where(GustavoAgendaSnapshot.snapshot_date == today_sp)
                    ).first()
                    if not exists:
                        audit_logger.info(f"GUSTAVO_SNAPSHOT: fallback do dia {today_sp} (app subiu após 19h).")
                        save_gustavo_snapshot_and_send(session, today_sp)

            # dorme até o próximo 19h
            nxt = _next_run_19h_sp(datetime.now(TZ))
            seconds = max(5, int((nxt - datetime.now(TZ)).total_seconds()))
            audit_logger.info(f"GUSTAVO_SNAPSHOT: próximo disparo em {nxt.isoformat()} (sleep {seconds}s).")
            pytime.sleep(seconds)

            # roda o snapshot do dia (19h)
            run_day = datetime.now(TZ).date()
            with Session(engine) as session:
                try:
                    audit_logger.info(f"GUSTAVO_SNAPSHOT: gerando snapshot do dia {run_day} (19h).")
                    save_gustavo_snapshot_and_send(session, run_day)
                except Exception as e:
                    audit_logger.exception(f"GUSTAVO_SNAPSHOT: erro ao gerar/enviar: {e}")

    t = threading.Thread(target=runner, daemon=True)
    t.start()

def validate_mapa_block_rules(session: Session, day: date, surgeon_id: int) -> str | None:
    # pega qualquer bloqueio que intersecte o dia
    blocks = session.exec(
        select(AgendaBlock).where(
            AgendaBlock.start_date <= day,
            AgendaBlock.end_date >= day,
        )
    ).all()

    if not blocks:
        return None

    # se existir algum "applies_to_all" no dia, já bloqueia
    for b in blocks:
        if b.applies_to_all:
            return f"Data bloqueada: {b.reason}"

    # caso contrário, bloqueia se o cirurgião estiver no grupo do bloqueio
    block_ids = [b.id for b in blocks if b.id is not None]
    if not block_ids:
        return None

    rel = session.exec(
        select(AgendaBlockSurgeon).where(
            AgendaBlockSurgeon.block_id.in_(block_ids),
            AgendaBlockSurgeon.surgeon_id == surgeon_id,
        )
    ).first()

    if rel:
        return "Data bloqueada para este profissional."

    return None

def compute_month_availability(
    session: Session,
    surgeon_id: int,
    month_ym: str,
    procedure_type: str,
) -> list[dict[str, str]]:
    """
    Retorna lista de datas operáveis no mês para o cirurgião + tipo de procedimento,
    respeitando:
      - validate_mapa_rules
      - validate_mapa_block_rules
      - reserva = agendamento
    Mostra só 🔴 (livre) e 🟡 (parcial). Dias lotados NÃO retornam.
    """

    selected_month, first_day, next_first, days = safe_selected_month(month_ym)

    surgeon = session.exec(select(User).where(User.id == surgeon_id)).first()
    if not surgeon:
        return []

    results: list[dict[str, str]] = []

    weekday_map = ["segunda-feira","terça-feira","quarta-feira","quinta-feira","sexta-feira","sábado","domingo"]

    # Para o emoji 🟡 precisamos saber a capacidade do dia (no caso do Gustavo)
    gustavo = session.exec(select(User).where(User.full_name == "Dr. Gustavo Aquino")).first()

    for d in days:
        # 1) bloqueios
        block_err = validate_mapa_block_rules(session, d, surgeon_id)
        if block_err:
            continue

        # 2) regras de agenda (usa o mesmo motor do create/edit)
        err = validate_mapa_rules(
            session=session,
            day=d,
            surgeon_id=surgeon_id,
            procedure_type=procedure_type,
            uses_hsr=False,   # consulta não define HSR; se quiser, adiciona no card depois
            exclude_entry_id=None,
        )
        if err:
            # inclui "dia fora do padrão" e "dia lotado" -> não aparece
            continue

        # 3) conta ocupações do cirurgião no dia (inclui reservas)
        cnt = session.exec(
            select(func.count()).select_from(SurgicalMapEntry).where(
                SurgicalMapEntry.day == d,
                SurgicalMapEntry.surgeon_id == surgeon_id,
            )
        ).one()

        # 4) define capacidade do dia para o emoji (só Gustavo pode gerar 🟡 com cap=2)
        cap = 1
        if gustavo and surgeon_id == gustavo.id:
            wd = d.weekday()
            if procedure_type == "Refinamento" and wd == 4:
                cap = 1
            else:
                cap = 2

        # só 🔴 e 🟡 (dias lotados não chegam aqui, mas garantimos)
        if cnt <= 0:
            emoji = "🔴"
        elif cnt < cap:
            emoji = "🟡"
        else:
            continue  # lotado -> não aparece

        results.append(
            {
                "day_iso": d.isoformat(),
                "label": d.strftime("%d/%m"),
                "human": f"{d.strftime('%d/%m/%Y')} - {weekday_map[d.weekday()]}",
                "emoji": emoji,
            }
        )

    return results

def compute_priority_card(session: Session) -> dict:
    today = datetime.now(TZ).date()
    end = today + timedelta(days=90)  # janela “hoje até +90”

    gustavo = session.exec(select(User).where(User.full_name == "Dr. Gustavo Aquino")).first()
    if not gustavo:
        return {"mode": "red", "items": []}

    # 1) pega bloqueios que intersectam a janela
    blocks = session.exec(
        select(AgendaBlock).where(
            AgendaBlock.start_date <= end,
            AgendaBlock.end_date >= today,
        )
    ).all()

    block_ids = [b.id for b in blocks if b.id is not None]

    rels = []
    if block_ids:
        rels = session.exec(
            select(AgendaBlockSurgeon).where(AgendaBlockSurgeon.block_id.in_(block_ids))
        ).all()

    surgeons_by_block: dict[int, list[int]] = {}
    for r in rels:
        surgeons_by_block.setdefault(r.block_id, []).append(r.surgeon_id)
        
    # ✅ precisamos do "surgeons" aqui dentro (escopo da função)
    surgeons = session.exec(
        select(User)
        .where(User.role == "doctor", User.is_active == True)
        .order_by(User.full_name)
    ).all()

    surgeons_name_by_id = {s.id: s.full_name for s in surgeons if s.id is not None}
    block_surgeons_map: dict[int, list[str]] = {}

    for b in blocks:
        if not b.id:
            continue
        if b.applies_to_all:
            block_surgeons_map[b.id] = ["Todos"]
        else:
            ids = surgeons_by_block.get(b.id, [])
            names = [surgeons_name_by_id.get(sid) for sid in ids]
            block_surgeons_map[b.id] = [n for n in names if n] or ["—"]

    blocked_days: set[date] = set()

    for b in blocks:
        # bloqueio geral
        if b.applies_to_all:
            start = max(b.start_date, today)
            finish = min(b.end_date, end)
            d = start
            while d <= finish:
                blocked_days.add(d)
                d += timedelta(days=1)
            continue

        # bloqueio por grupo: só conta se o Gustavo estiver no grupo
        if gustavo and gustavo.id in surgeons_by_block.get(b.id or -1, []):
            start = max(b.start_date, today)
            finish = min(b.end_date, end)
            d = start
            while d <= finish:
                blocked_days.add(d)
                d += timedelta(days=1)

    days = []
    for i in range(0, 91):  # inclui a data final (ex.: 04/12 a 04/03)
        d = today + timedelta(days=i)
        if d.weekday() not in (0, 2):  # só segunda (0) e quarta (2)
            continue
        if d in blocked_days:
            continue
        days.append(d)

    counts: dict[date, int] = {}
    for d in session.exec(
        select(SurgicalMapEntry.day).where(
            SurgicalMapEntry.day >= today,
            SurgicalMapEntry.day <= end,
            SurgicalMapEntry.surgeon_id == gustavo.id,
        )
    ).all():
        counts[d] = counts.get(d, 0) + 1

    zeros = [d for d in days if counts.get(d, 0) == 0]
    if zeros:
        return {"mode": "red", "items": [f"🔴 {d.strftime('%d/%m/%Y')}" for d in zeros]}

    ones = [d for d in days if counts.get(d, 0) == 1]
    if ones:
        return {
            "mode": "yellow",
            "items": [f"🟡 {_weekday_pt(d.weekday())} {d.strftime('%d/%m/%Y')}" for d in ones],
        }

    # se não tem zeros nem ones, então está tudo com 2+
    return {"mode": "green", "items": []}

def migrate_sqlite_schema(engine):
    """
    Migração idempotente do SQLite.
    Ajusta a tabela agendablock (antiga) para o novo modelo:
      - start_date / end_date
      - reason
      - applies_to_all
    E cria a tabela de relação AgendaBlockSurgeon se não existir.
    """

    def _has_column(conn, table: str, col: str) -> bool:
        rows = conn.exec_driver_sql(f"PRAGMA table_info({table})").fetchall()
        return any(r[1] == col for r in rows)  # r[1] = nome da coluna

    def _add_column_if_missing(conn, table: str, col: str, col_type: str):
        if not _has_column(conn, table, col):
            conn.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN {col} {col_type}")

    with engine.begin() as conn:
        # Se a tabela ainda não existir, create_db_and_tables() vai criar.
        # Aqui só migramos se ela existir.
        tables = conn.exec_driver_sql(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='agendablock';"
        ).fetchall()
        if not tables:
            return

        # --- Novas colunas do modelo atual ---
        _add_column_if_missing(conn, "agendablock", "start_date", "DATE")
        _add_column_if_missing(conn, "agendablock", "end_date", "DATE")
        _add_column_if_missing(conn, "agendablock", "reason", "TEXT")
        _add_column_if_missing(conn, "agendablock", "applies_to_all", "INTEGER DEFAULT 0")

        # --- Backfill a partir do schema antigo, se existir ---
        # Antigo: data, motivo, profissional
        has_old_date = _has_column(conn, "agendablock", "data")
        has_old_reason = _has_column(conn, "agendablock", "motivo")
        has_old_prof = _has_column(conn, "agendablock", "profissional")

        if has_old_date:
            conn.exec_driver_sql("""
                UPDATE agendablock
                   SET start_date = COALESCE(start_date, data),
                       end_date   = COALESCE(end_date, data)
                 WHERE data IS NOT NULL;
            """)

        if has_old_reason:
            conn.exec_driver_sql("""
                UPDATE agendablock
                   SET reason = COALESCE(reason, motivo)
                 WHERE motivo IS NOT NULL;
            """)

        if has_old_prof:
            # Se profissional='todos' no schema antigo, vira applies_to_all=1
            conn.exec_driver_sql("""
                UPDATE agendablock
                   SET applies_to_all = CASE
                        WHEN applies_to_all IS NULL THEN
                            CASE WHEN lower(profissional)='todos' THEN 1 ELSE 0 END
                        ELSE applies_to_all
                       END;
            """)

        # --- Criar tabela de relacionamento (multi-cirurgião) ---
        conn.exec_driver_sql("""
            CREATE TABLE IF NOT EXISTS agendablocksurgeon (
                block_id INTEGER NOT NULL,
                surgeon_id INTEGER NOT NULL,
                PRIMARY KEY (block_id, surgeon_id)
            );
        """)

def get_commercial_period(month_year: str) -> tuple[datetime, datetime]:
    """
    Retorna (start_datetime_utc_naive, end_datetime_utc_naive) do período comercial:
    - padrão: dia 25 do mês anterior até dia 24 do mês selecionado
    - exceção: Janeiro/2026 começa em 06/01/2026
    """

    tz = ZoneInfo("America/Sao_Paulo")
    year, month = map(int, month_year.split("-"))

    # início padrão: dia 25 do mês anterior (em horário SP)
    if month == 1:
        start_sp = datetime(year - 1, 12, 25, 0, 0, 0, tzinfo=tz)
    else:
        start_sp = datetime(year, month - 1, 25, 0, 0, 0, tzinfo=tz)

    # fim padrão: dia 24 do mês atual (em horário SP)
    end_sp = datetime(year, month, 24, 23, 59, 59, tzinfo=tz)

    # 🚨 EXCEÇÃO: Janeiro/2026
    if year == 2026 and month == 1:
        start_sp = datetime(2026, 1, 6, 0, 0, 0, tzinfo=tz)

    # Converte para UTC e remove tzinfo (para bater com created_at = utcnow() naive)
    start_utc_naive = start_sp.astimezone(timezone.utc).replace(tzinfo=None)
    end_utc_naive = end_sp.astimezone(timezone.utc).replace(tzinfo=None)

    return start_utc_naive, end_utc_naive

@app.get("/comissoes")
def comissoes_page(
    request: Request,
    month_year: str,
    seller_id: str  | None = None,
    session: Session = Depends(get_session),
):
    """
    Relatório de comissões por cirurgia agendada:
    - procedure_type == "Cirurgia"
    - não pode ser reserva (is_pre_reservation == False)
    - período comercial (25->24, com exceção jan/2026 a partir de 06/01/2026)
    - agrupado por vendedor (created_by_id)
    """

    user = get_current_user(request, session)
    if not user:
        return redirect("/login")
    require(user.role in ("admin", "comissao"))

    period_start, period_end = get_commercial_period(month_year)
    
    seller_id_int: int | None = None
    if seller_id and seller_id.strip():
        try:
            seller_id_int = int(seller_id)
        except ValueError:
            seller_id_int = None

    # 1) Subquery: pega o primeiro agendamento (created_at mais antigo) por paciente
    first_created_subq = (
        select(
            SurgicalMapEntry.patient_name,
            func.min(SurgicalMapEntry.created_at).label("first_created_at"),
        )
        .where(
            SurgicalMapEntry.procedure_type == "Cirurgia",
            SurgicalMapEntry.is_pre_reservation == False,
            SurgicalMapEntry.patient_name.is_not(None),
            SurgicalMapEntry.patient_name != "",
        )
        .group_by(SurgicalMapEntry.patient_name)
        .subquery()
    )

    # 2) Query principal: só traz as cirurgias que são o PRIMEIRO agendamento do paciente
    q = (
        select(SurgicalMapEntry)
        .join(
            first_created_subq,
            (SurgicalMapEntry.patient_name == first_created_subq.c.patient_name)
            & (SurgicalMapEntry.created_at == first_created_subq.c.first_created_at),
        )
        .where(
            SurgicalMapEntry.created_at >= period_start,
            SurgicalMapEntry.created_at <= period_end,
        )
    )

    if seller_id_int is not None:
        q = q.where(SurgicalMapEntry.created_by_id == seller_id_int)

    entries = session.exec(q).all()

    # mapa de usuários (para resolver nome do vendedor pelo created_by_id)
    users = session.exec(select(User)).all()
    users_by_id = {u.id: u for u in users}

    # lista de vendedores para o filtro (somente quem pode “vender”)
    sellers = [u for u in users if u.role in ("admin", "surgery") and u.is_active]

    # Agrupamento por vendedor (nome vem do users_by_id)
    grouped: dict[str, list[SurgicalMapEntry]] = {}

    for e in entries:
        seller_name = "Sem vendedor"
        if e.created_by_id and e.created_by_id in users_by_id:
            seller_name = users_by_id[e.created_by_id].full_name

        grouped.setdefault(seller_name, []).append(e)

    # Ordenar cirurgias dentro de cada vendedor (mais recentes primeiro)
    for k in grouped:
        grouped[k].sort(key=lambda x: x.created_at, reverse=True)

    return templates.TemplateResponse(
        "comissoes.html",
        {
            "request": request,
            "current_user": user,
            "month_year": month_year,
            "period_start": period_start,
            "period_end": period_end,
            "grouped": grouped,
            "total": len(entries),
            "sellers": sellers,
            "seller_id": seller_id,
            "users_by_id": users_by_id,  # opcional (se quiser mostrar algo extra no template)
        },
    )

@app.on_event("startup")
def on_startup():
    create_db_and_tables()

    # ✅ MIGRAÇÃO DO BANCO ANTIGO -> NOVO
    migrate_sqlite_schema(engine)

    with Session(engine) as session:
        seed_if_empty(session)

    # ✅ Snapshot diário (19h) - Relatório Dr. Gustavo
    start_gustavo_snapshot_scheduler()

@app.get("/", response_class=HTMLResponse)
def home(request: Request, session: Session = Depends(get_session)):
    user = get_current_user(request, session)
    if not user:
        return redirect("/login")

    if user.role == "admin":
        return redirect("/admin")
    if user.role == "doctor":
        return redirect("/doctor")
    if user.role == "surgery":
        return redirect("/mapa")
    if user.role == "comissao":
        # redireciona para o mês atual (você pode manter manual também)
        today = datetime.now(ZoneInfo("America/Sao_Paulo")).date()
        # regra do “mês comercial”: se hoje >= 25, isso pertence ao próximo month_year
        if today.day >= 25:
            y = today.year + (1 if today.month == 12 else 0)
            m = 1 if today.month == 12 else today.month + 1
        else:
            y = today.year
            m = today.month
        month_year = f"{y:04d}-{m:02d}"
        return redirect(f"/comissoes?month_year={month_year}")

    return redirect("/login")


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(
        "login.html", {"request": request, "current_user": None}
    )


@app.post("/login", response_class=HTMLResponse)
def login_action(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    session: Session = Depends(get_session),
):
    user = session.exec(
        select(User).where(User.username == username, User.is_active == True)
    ).first()
    if not user or not verify_password(password, user.password_hash):
        audit_event(
            request,
            user,  # pode ser None (ok)
            "login_failed",
            success=False,
            message="Usuário ou senha inválidos.",
            extra={"username": username},
        )
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Usuário ou senha inválidos.", "current_user": None},
            status_code=401,
        )
    request.session["user_id"] = user.id
    audit_event(request, user, "login_success")
    return redirect("/")


@app.post("/logout")
def logout(request: Request, session: Session = Depends(get_session)):
    user = get_current_user(request, session)
    audit_event(request, user, "logout")
    request.session.clear()
    return redirect("/login")


def availability_context(session: Session, day: date, role: str):
    rooms = session.exec(select(Room).order_by(Room.id)).all()
    slots = build_slots_for_day(day)

    day_start = datetime.combine(day, time(0, 0))   # NAIVE p/ casar com o SQLite
    day_end = day_start + timedelta(days=1)

    reservations = session.exec(
        select(Reservation).where(
            Reservation.start_time >= day_start, Reservation.start_time < day_end
        )
    ).all()

    pending_reqs = session.exec(
        select(ReservationRequest).where(
            ReservationRequest.status == "pending",
            ReservationRequest.requested_start >= day_start,
            ReservationRequest.requested_start < day_end,
        )
    ).all()

    occupancy: Dict[int, Dict[str, Dict[str, Any]]] = {}
    
    # Mapa de usuários por id (para mostrar o nome do médico nas reservas)
    user_by_id = {u.id: u for u in session.exec(select(User)).all()}

    for r in reservations:
        for k in slot_keys(r.start_time):
            occupancy.setdefault(r.room_id, {})[k] = {
                "type": "reservation",
                "doctor_name": user_by_id.get(r.doctor_id).full_name if user_by_id.get(r.doctor_id) else "Médico",
            }

    for rq in pending_reqs:
        for k in slot_keys(rq.requested_start):
            occupancy.setdefault(rq.room_id, {})[k] = {
                "type": "request",
                "doctor_name": user_by_id.get(rq.doctor_id).full_name if user_by_id.get(rq.doctor_id) else "Médico",
            }

    doctors = session.exec(
        select(User)
        .where(User.role == "doctor", User.is_active == True)
        .order_by(User.full_name)
    ).all()

    weekday_map = [
        "segunda-feira",
        "terça-feira",
        "quarta-feira",
        "quinta-feira",
        "sexta-feira",
        "sábado",
        "domingo",
    ]
    date_human = f"{day.strftime('%d/%m/%Y')} · {weekday_map[day.weekday()]}"

    return {
        "rooms": rooms,
        "slots": slots,
        "occupancy": occupancy,
        "doctors": doctors,
        "role": role,
        "date_human": date_human,
    }

@app.get("/bloqueios", response_class=HTMLResponse)
def bloqueios_page(
    request: Request,
    session: Session = Depends(get_session),
):
    user = get_current_user(request, session)
    if not user:
        return redirect("/login")
    require(user.role in ("admin", "surgery"), "Acesso restrito.")

    surgeons = session.exec(
        select(User)
        .where(User.role == "doctor", User.is_active == True)
        .order_by(User.full_name)
    ).all()

    blocks = session.exec(
        select(AgendaBlock).order_by(AgendaBlock.start_date.asc())
    ).all()
    
        # ===== MAPA DE CIRURGIÕES POR BLOQUEIO =====
    block_ids = [b.id for b in blocks if b.id is not None]

    rels = []
    if block_ids:
        rels = session.exec(
            select(AgendaBlockSurgeon).where(
                AgendaBlockSurgeon.block_id.in_(block_ids)
            )
        ).all()

    # block_id -> lista de nomes dos cirurgiões
    block_surgeons_map: dict[int, list[str]] = {}

    if rels:
        surgeons_by_id = {s.id: s.full_name for s in surgeons}

        for r in rels:
            name = surgeons_by_id.get(r.surgeon_id)
            if name:
                block_surgeons_map.setdefault(r.block_id, []).append(name)


    # ===== SUPORTE A EDIÇÃO DE BLOQUEIO =====
    edit_block = None
    selected_surgeons = []

    edit_id = request.query_params.get("edit")
    if edit_id and edit_id.isdigit():
        edit_block = session.get(AgendaBlock, int(edit_id))

        if edit_block and edit_block.id:
            rels = session.exec(
                select(AgendaBlockSurgeon).where(
                    AgendaBlockSurgeon.block_id == edit_block.id
                )
            ).all()
            selected_surgeons = [r.surgeon_id for r in rels]

    return templates.TemplateResponse(
        "bloqueios.html",
        {
            "request": request,
            "current_user": user,
            "surgeons": surgeons,
            "blocks": blocks,
            "edit_block": edit_block,
            "selected_surgeons": selected_surgeons,
            "block_surgeons_map": block_surgeons_map,
        },
    )
    

@app.post("/bloqueios")
def registrar_bloqueio(
    request: Request,
    data_inicio: str = Form(...),
    data_fim: str = Form(...),
    motivo: str = Form(...),
    surgeons: list[str] = Form([]),
    session: Session = Depends(get_session),
):
    user = get_current_user(request, session)
    if not user:
        return redirect("/login")
    require(user.role in ("admin", "surgery"), "Acesso restrito.")

    # converte "YYYY-MM-DD" para date
    start_date = date.fromisoformat(data_inicio)
    end_date = date.fromisoformat(data_fim)
    
    if end_date < start_date:
        return redirect("/bloqueios")
    
    applies_all = (len(surgeons) == 0)

    row = AgendaBlock(
        day=start_date,
        start_date=start_date,
        end_date=end_date,
        reason=motivo.strip(),
        applies_to_all=applies_all,
        created_by_id=user.id,
    )
    session.add(row)
    session.commit()

    if not applies_all:
        for sid in surgeons:
            session.add(AgendaBlockSurgeon(block_id=row.id, surgeon_id=int(sid)))
        session.commit()

    return redirect("/bloqueios")

@app.post("/bloqueios/{block_id}/update")
def bloqueio_update(
    request: Request,
    block_id: int,
    data_inicio: str = Form(...),
    data_fim: str = Form(...),
    motivo: str = Form(...),
    surgeons: list[str] = Form([]),
    session: Session = Depends(get_session),
):
    user = get_current_user(request, session)
    if not user:
        return redirect("/login")
    require(user.role in ("admin", "surgery"), "Acesso restrito.")

    b = session.get(AgendaBlock, block_id)
    if not b:
        return redirect("/bloqueios")

    b.start_date = date.fromisoformat(data_inicio)
    b.day = b.start_date
    b.end_date = date.fromisoformat(data_fim)
    if b.end_date < b.start_date:
        return redirect("/bloqueios")
    b.reason = motivo.strip()
    b.applies_to_all = (len(surgeons) == 0)

    session.add(b)
    session.commit()

    # limpa relações antigas
    session.exec(
        delete(AgendaBlockSurgeon).where(AgendaBlockSurgeon.block_id == block_id)
    )
    session.commit()

    # recria relações
    if not b.applies_to_all:
        for sid in surgeons:
            session.add(AgendaBlockSurgeon(block_id=block_id, surgeon_id=int(sid)))
        session.commit()

    return redirect("/bloqueios")

@app.post("/bloqueios/{block_id}/delete")
def bloqueio_delete(
    request: Request,
    block_id: int,
    session: Session = Depends(get_session),
):
    user = get_current_user(request, session)
    if not user:
        return redirect("/login")
    require(user.role in ("admin", "surgery"), "Acesso restrito.")

    # apaga relações
    session.exec(
        delete(AgendaBlockSurgeon).where(AgendaBlockSurgeon.block_id == block_id)
    )
    session.commit()

    # apaga bloco
    b = session.get(AgendaBlock, block_id)
    if b:
        session.delete(b)
        session.commit()

    return redirect("/bloqueios")

@app.get("/doctor", response_class=HTMLResponse)
def doctor_page(
    request: Request,
    date: Optional[str] = None,
    session: Session = Depends(get_session),
):
    user = get_current_user(request, session)
    if not user:
        return redirect("/login")
    require(user.role == "doctor", "Acesso restrito aos médicos.")

    selected, day = safe_selected_and_day(date)
    ctx = availability_context(session, day, role="doctor")
    audit_event(request, user, "doctor_page_view", extra={"date": selected})

    return templates.TemplateResponse(
        "doctor.html",
        {
            "request": request,
            "current_user": user,
            "title": "Agenda",
            "selected_date": selected,
            **ctx,
        },
    )

@app.get("/doctor/availability", response_class=HTMLResponse)
def doctor_availability(
    request: Request,
    date: Optional[str] = None,
    session: Session = Depends(get_session),
):
    user = get_current_user(request, session)
    if not user:
        return redirect("/login")
    require(user.role == "doctor", "Acesso restrito aos médicos.")

    _, day = safe_selected_and_day(date)
    ctx = availability_context(session, day, role="doctor")

    return templates.TemplateResponse(
        "partials/availability.html",
        {"request": request, "current_user": user, **ctx},
    )


@app.post("/doctor/request")
def doctor_request(
    request: Request,
    room_id: int = Form(...),
    start_iso: str = Form(...),
    session: Session = Depends(get_session),
):
    user = get_current_user(request, session)
    if not user:
        return redirect("/login")
    require(user.role == "doctor", "Acesso restrito aos médicos.")

    start_dt = to_db_dt(datetime.fromisoformat(start_iso))
    end_dt = start_dt + timedelta(minutes=SLOT_MINUTES)

    existing_res = session.exec(
        select(Reservation).where(
            Reservation.room_id == room_id, Reservation.start_time == start_dt
        )
    ).first()
    existing_req = session.exec(
        select(ReservationRequest).where(
            ReservationRequest.room_id == room_id,
            ReservationRequest.requested_start == start_dt,
            ReservationRequest.status == "pending",
        )
    ).first()
    if existing_res or existing_req:
        audit_event(
            request,
            user,
            "request_conflict",
            success=False,
            message="Slot já ocupado (reserva ou solicitação pendente).",
            room_id=room_id,
            start_time=start_dt,
            end_time=end_dt,
        )
        return redirect(f"/doctor?date={start_dt.date().isoformat()}")


    rq = ReservationRequest(
        room_id=room_id,
        doctor_id=user.id,
        requested_start=start_dt,
        requested_end=end_dt,
        status="pending",
    )
    session.add(rq)
    session.commit()

    audit_event(
        request,
        user,
        "request_created",
        room_id=room_id,
        target_type="request",
        target_id=rq.id,
        start_time=start_dt,
        end_time=end_dt,
    )

    return redirect("/doctor")


@app.get("/admin", response_class=HTMLResponse)
def admin_page(
    request: Request,
    date: Optional[str] = None,
    session: Session = Depends(get_session),
):
    user = get_current_user(request, session)
    if not user:
        return redirect("/login")
    require(user.role == "admin", "Acesso restrito à secretaria/admin.")

    selected, day = safe_selected_and_day(date)
    ctx = availability_context(session, day, role="admin")

    pending = session.exec(
        select(ReservationRequest)
        .where(ReservationRequest.status == "pending")
        .order_by(ReservationRequest.created_at.desc())
    ).all()

    rooms = {r.id: r for r in session.exec(select(Room)).all()}
    users = {u.id: u for u in session.exec(select(User)).all()}

    pending_view = []
    audit_event(request, user, "admin_page_view", extra={"date": selected})
    for r in pending:
        dt = r.requested_start.replace(tzinfo=TZ)
        pending_view.append(
            {
                "id": r.id,
                "doctor_name": users.get(r.doctor_id).full_name
                if users.get(r.doctor_id)
                else "Médico",
                "room_name": rooms.get(r.room_id).name if rooms.get(r.room_id) else "Sala",
                "date_str": dt.strftime("%d/%m/%Y"),
                "time_str": dt.strftime("%H:%M"),
            }
        )

    return templates.TemplateResponse(
        "admin.html",
        {
            "request": request,
            "current_user": user,
            "title": "Agenda",
            "selected_date": selected,
            "pending_requests": pending_view,
            **ctx,
        },
    )


@app.get("/admin/availability", response_class=HTMLResponse)
def admin_availability(
    request: Request,
    date: Optional[str] = None,
    session: Session = Depends(get_session),
):
    user = get_current_user(request, session)
    if not user:
        return redirect("/login")
    require(user.role == "admin", "Acesso restrito à secretaria/admin.")

    _, day = safe_selected_and_day(date)
    ctx = availability_context(session, day, role="admin")

    return templates.TemplateResponse(
        "partials/availability.html",
        {"request": request, "current_user": user, **ctx},
    )


@app.post("/admin/reserve")
def admin_reserve(
    request: Request,
    room_id: int = Form(...),
    doctor_id: int = Form(...),
    start_iso: str = Form(...),
    session: Session = Depends(get_session),
):
    user = get_current_user(request, session)
    if not user:
        return redirect("/login")
    require(user.role == "admin", "Acesso restrito à secretaria/admin.")

    start_dt = to_db_dt(datetime.fromisoformat(start_iso))
    end_dt = start_dt + timedelta(minutes=SLOT_MINUTES)

    existing = session.exec(
        select(Reservation).where(
            Reservation.room_id == room_id, Reservation.start_time == start_dt
        )
    ).first()
    if existing:
        audit_event(
            request,
            user,
            "admin_reserve_conflict",
            success=False,
            message="Já existe reserva nesse horário.",
            room_id=room_id,
            start_time=start_dt,
            end_time=end_dt,
            extra={"doctor_id": doctor_id},
        )
        return redirect(f"/admin?date={start_dt.date().isoformat()}")


    res = Reservation(
        room_id=room_id,
        doctor_id=doctor_id,
        created_by_id=user.id,
        start_time=start_dt,
        end_time=end_dt,
    )
    session.add(res)
    session.commit()

    audit_event(
        request,
        user,
        "admin_reserve_created",
        room_id=room_id,
        target_type="reservation",
        target_id=res.id,
        start_time=start_dt,
        end_time=end_dt,
        extra={"doctor_id": doctor_id},
    )

    return redirect("/admin")


@app.post("/admin/requests/{request_id}/approve")
def approve_request(request: Request, request_id: int, session: Session = Depends(get_session)):
    user = get_current_user(request, session)
    if not user:
        return redirect("/login")
    require(user.role == "admin")

    rq = session.get(ReservationRequest, request_id)
    if not rq or rq.status != "pending":
        return redirect("/admin")

    existing = session.exec(
        select(Reservation).where(
            Reservation.room_id == rq.room_id,
            Reservation.start_time == rq.requested_start,
        )
    ).first()

    if existing:
        rq.status = "denied"
        rq.decided_by_id = user.id
        rq.decided_at = datetime.utcnow()
        session.add(rq)
        session.commit()
        audit_event(
            request,
            user,
            "request_approve_conflict_denied",
            success=False,
            message="Havia reserva no slot; solicitação negada automaticamente.",
            room_id=rq.room_id,
            target_type="request",
            target_id=rq.id,
            start_time=rq.requested_start,
            end_time=rq.requested_end,
        )
        return redirect("/admin")

    res = Reservation(
        room_id=rq.room_id,
        doctor_id=rq.doctor_id,
        created_by_id=user.id,
        start_time=rq.requested_start,
        end_time=rq.requested_end,
    )
    session.add(res)

    rq.status = "approved"
    rq.decided_by_id = user.id
    rq.decided_at = datetime.utcnow()
    session.add(rq)

    session.commit()
    audit_event(
        request,
        user,
        "request_approved",
        room_id=rq.room_id,
        target_type="request",
        target_id=rq.id,
        start_time=rq.requested_start,
        end_time=rq.requested_end,
        extra={"reservation_id": res.id},
    )

    return redirect("/admin")


@app.post("/admin/requests/{request_id}/deny")
def deny_request(request: Request, request_id: int, session: Session = Depends(get_session)):
    user = get_current_user(request, session)
    if not user:
        return redirect("/login")
    require(user.role == "admin")

    rq = session.get(ReservationRequest, request_id)
    if rq and rq.status == "pending":
        rq.status = "denied"
        rq.decided_by_id = user.id
        rq.decided_at = datetime.utcnow()
        session.add(rq)
        session.commit()
        audit_event(
            request,
            user,
            "request_denied",
            room_id=rq.room_id,
            target_type="request",
            target_id=rq.id,
            start_time=rq.requested_start,
            end_time=rq.requested_end,
        )

    return redirect("/admin")

@app.get("/mapa", response_class=HTMLResponse)
def mapa_page(
    request: Request,
    month: Optional[str] = None,
    err: str | None = None,
    av_do: Optional[str] = None,
    av_surgeon_id: Optional[int] = None,
    av_month: Optional[str] = None,
    av_procedure_type: Optional[str] = None,
    session: Session = Depends(get_session),
):
    user = get_current_user(request, session)
    if not user:
        return redirect("/login")
    require(user.role in ("admin", "surgery"), "Acesso restrito ao Mapa Cirúrgico.")

    selected_month, first_day, next_first, days = safe_selected_month(month)

    audit_event(
        request,
        user,
        "mapa_page_view",
        extra={"month": selected_month},
    )
    surgeons = session.exec(
        select(User)
        .where(User.role == "doctor", User.is_active == True)
        .order_by(User.full_name)
    ).all()
    
    sellers = session.exec(
        select(User).where(User.role == "surgery", User.is_active == True).order_by(User.full_name)
    ).all()
    
    users_all = session.exec(select(User)).all()
    users_by_id = {u.id: u for u in users_all if u.id is not None}

    entries = session.exec(
        select(SurgicalMapEntry)
        .where(SurgicalMapEntry.day >= first_day, SurgicalMapEntry.day < next_first)
        .order_by(SurgicalMapEntry.day, SurgicalMapEntry.time_hhmm, SurgicalMapEntry.created_at)
    ).all()

    entries_by_day: dict[str, list[SurgicalMapEntry]] = {}
    for e in entries:
        entries_by_day.setdefault(e.day.isoformat(), []).append(e)

    # pega bloqueios que intersectam o mês
    blocks = session.exec(
        select(AgendaBlock)
        .where(
            AgendaBlock.start_date <= (next_first - timedelta(days=1)),
            AgendaBlock.end_date >= first_day,
        )
        .order_by(AgendaBlock.start_date, AgendaBlock.created_at)
    ).all()

    # relações (multi-cirurgiões)
    block_ids = [b.id for b in blocks if b.id is not None]
    rels = []
    if block_ids:
        rels = session.exec(
            select(AgendaBlockSurgeon).where(AgendaBlockSurgeon.block_id.in_(block_ids))
        ).all()

    surgeons_by_block: dict[int, list[int]] = {}
    for r in rels:
        surgeons_by_block.setdefault(r.block_id, []).append(r.surgeon_id)
    
    # ✅ block_id -> lista de nomes dos cirurgiões (para exibir no mapa.html)
    surgeons_by_id = {s.id: s.full_name for s in surgeons if s.id is not None}
    block_surgeons_map: dict[int, list[str]] = {}

    for b in blocks:
        if not b.id:
            continue
        if b.applies_to_all:
            block_surgeons_map[b.id] = ["Todos"]
        else:
            ids = surgeons_by_block.get(b.id, [])
            names = [surgeons_by_id.get(sid) for sid in ids]
            block_surgeons_map[b.id] = [n for n in names if n] or ["—"]

    blocks_by_day: dict[str, list[AgendaBlock]] = {}
    blocked_all_days: set[str] = set()
    blocked_surgeons_by_day: dict[str, list[int]] = {}

    # expande cada bloqueio para os dias do mês (no máximo 31 dias)
    month_end = next_first - timedelta(days=1)

    for b in blocks:
        start = max(b.start_date, first_day)
        end = min(b.end_date, month_end)

        d = start
        while d <= end:
            k = d.isoformat()
            blocks_by_day.setdefault(k, []).append(b)

            if b.applies_to_all:
                blocked_all_days.add(k)
            else:
                ids = surgeons_by_block.get(b.id or -1, [])
                if ids:
                    blocked_surgeons_by_day.setdefault(k, []).extend(ids)

            d += timedelta(days=1)

    priority = compute_priority_card(session)

    weekday_map = ["segunda-feira","terça-feira","quarta-feira","quinta-feira","sexta-feira","sábado","domingo"]

    # =========================
    # Consulta de Disponibilidade (card)
    # =========================
    av_results: list[dict[str, str]] = []
    av_selected_month = av_month or selected_month
    av_selected_surgeon_id = av_surgeon_id
    av_selected_procedure_type = av_procedure_type or "Cirurgia"

    if av_do == "1" and av_selected_surgeon_id:
        av_results = compute_month_availability(
            session=session,
            surgeon_id=int(av_selected_surgeon_id),
            month_ym=av_selected_month,
            procedure_type=av_selected_procedure_type,
        )
    
    return templates.TemplateResponse(
        "mapa.html",
        {
            "request": request,
            "current_user": user,
            "fmt_brasilia": fmt_brasilia,
            "err": err,
            "title": "Mapa Cirúrgico",
            "selected_month": selected_month,   # YYYY-MM
            "days": days,
            "entries_by_day": entries_by_day,   # dict[str, list]
            "surgeons": surgeons,
            "weekday_map": weekday_map,
            "users_by_id": users_by_id,
            "blocks": blocks,
            "blocks_by_day": blocks_by_day,
            "block_surgeons_map": block_surgeons_map,  # ✅ NOVO
            "blocked_all_days": blocked_all_days,
            "blocked_surgeons_by_day": blocked_surgeons_by_day,
            "priority_mode": priority["mode"],
            "priority_items": priority["items"],
            "sellers": sellers,
            "blocked_all_days": blocked_all_days,  # set[str] -> "2026-01-15"
            "blocked_surgeons_by_day": blocked_surgeons_by_day,  # dict[str, list[int]]
            "av_selected_month": av_selected_month,
            "av_selected_surgeon_id": av_selected_surgeon_id,
            "av_selected_procedure_type": av_selected_procedure_type,
            "av_results": av_results,
        },
    )


@app.post("/mapa/create")
def mapa_create(
    request: Request,
    day_iso: str = Form(...),
    mode: str = Form("book"),
    time_hhmm: Optional[str] = Form(None),
    patient_name: str = Form(...),
    surgeon_id: int = Form(...),
    procedure_type: str = Form(...),
    location: str = Form(...),
    uses_hsr: Optional[str] = Form(None),
    has_lodging: Optional[str] = Form(None),
    seller_id: Optional[int] = Form(None),
    force_override: Optional[str] = Form(None),
    session: Session = Depends(get_session),
):
    user = get_current_user(request, session)
    if not user:
        return redirect("/login")
    require(user.role in ("admin", "surgery"))
    
    is_johnny = (user.username == "johnny.ge")
    override = is_johnny and bool(force_override)

    # ✅ regra do vendedor (depois do user existir!)
    if user.username != "johnny.ge":
        seller_id_final = user.id
    else:
        seller_id_final = int(seller_id) if seller_id else user.id

    day = date.fromisoformat(day_iso)
    
    is_pre = (mode == "reserve")

    block_err = validate_mapa_block_rules(session, day, surgeon_id)
    if block_err and not override:
        month = day.strftime("%Y-%m")
        from urllib.parse import quote
        audit_event(request, user, "surgical_map_blocked_by_agenda_block", success=False, message=block_err)

        return redirect(
            f"/mapa?month={month}&open=1"
            f"&err={quote(block_err)}"
            f"&day_iso={quote(day_iso)}"
            f"&mode={quote(mode)}"
            f"&time_hhmm={quote(time_hhmm or '')}"
            f"&patient_name={quote(patient_name)}"
            f"&surgeon_id={surgeon_id}"
            f"&procedure_type={quote(procedure_type)}"
            f"&location={quote(location)}"
            f"&uses_hsr={1 if uses_hsr else 0}"
            f"&has_lodging={1 if has_lodging else 0}" 
            f"&seller_id={seller_id_final}"
        )

    # se passou com override, registra auditoria
    if block_err and override:
        audit_event(request, user, "surgical_map_override_agenda_block", success=True, message=block_err)

    err = validate_mapa_rules(session, day, surgeon_id, procedure_type, uses_hsr=bool(uses_hsr))
    if err and not override:
        month = day.strftime("%Y-%m")
        audit_event(
            request,
            user,
            "surgical_map_create_validation_error",
            success=False,
            message=err,
            extra={
                "day": day_iso,
                "time_hhmm": time_hhmm,
                "patient_name": patient_name,
                "surgeon_id": surgeon_id,
                "procedure_type": procedure_type,
                "location": location,
                "uses_hsr": bool(uses_hsr),
                "mode": mode,
            },
        )
        from urllib.parse import quote
        return redirect(
            f"/mapa?month={month}&open=1"
            f"&err={quote(err)}"
            f"&day_iso={quote(day_iso)}"
            f"&mode={quote(mode)}"
            f"&time_hhmm={quote(time_hhmm or '')}"
            f"&patient_name={quote(patient_name)}"
            f"&surgeon_id={surgeon_id}"
            f"&procedure_type={quote(procedure_type)}"
            f"&location={quote(location)}"
            f"&uses_hsr={1 if uses_hsr else 0}"
            f"&has_lodging={1 if has_lodging else 0}" 
            f"&seller_id={seller_id_final}"
        )
    
    time_hhmm = (time_hhmm or "").strip()  # normaliza
    
    row = SurgicalMapEntry(
        day=day,
        time_hhmm=(time_hhmm or None),
        patient_name=patient_name.strip().upper(),
        surgeon_id=surgeon_id,
        procedure_type=procedure_type,
        location=location,
        uses_hsr=bool(uses_hsr),
        is_pre_reservation=is_pre,
        created_by_id=seller_id_final,
    )
    
    session.add(row)
    session.commit()

    audit_event(
        request,
        user,
        "surgical_map_created",
        target_type="surgical_map",
        target_id=row.id,
        extra={
            "day": day_iso,
            "patient_name": patient_name,
            "surgeon_id": surgeon_id,
            "procedure_type": procedure_type,
            "location": location,
            "uses_hsr": bool(uses_hsr),
        },
    )

    month = day.strftime("%Y-%m")
    if has_lodging:
        from urllib.parse import quote
        # check-in e check-out default: 1 dia (você pode mudar depois)
        ci = day.isoformat()
        co = (day + timedelta(days=1)).isoformat()
        return redirect(
            f"/hospedagem?month={quote(month)}&open=1"
            f"&unit={quote('')}"
            f"&check_in={quote(ci)}&check_out={quote(co)}"
            f"&patient_name={quote(patient_name.strip().upper())}"
            f"&is_pre_reservation={(1 if is_pre else 0)}"
            f"&surgery_entry_id={row.id}"
        )

    return redirect(f"/mapa?month={month}")

@app.post("/mapa/update/{entry_id}")
def mapa_update(
    request: Request,
    entry_id: int,
    day_iso: str = Form(...),
    mode: str = Form("book"),
    time_hhmm: Optional[str] = Form(None),
    patient_name: str = Form(...),
    surgeon_id: int = Form(...),
    procedure_type: str = Form(...),
    location: str = Form(...),
    uses_hsr: Optional[str] = Form(None),
    has_lodging: Optional[str] = Form(None),  
    seller_id: Optional[int] = Form(None),
    force_override: Optional[str] = Form(None),
    session: Session = Depends(get_session),
):
    user = get_current_user(request, session)
    if not user:
        return redirect("/login")
    require(user.role in ("admin", "surgery"))
    
    is_johnny = (user.username == "johnny.ge")
    override = is_johnny and bool(force_override)
    
    # ✅ regra do vendedor (mesma do /mapa/create)
    if user.username != "johnny.ge":
        seller_id_final = user.id
    else:
        seller_id_final = int(seller_id) if seller_id else user.id

    row = session.get(SurgicalMapEntry, entry_id)
    if not row:
        return redirect("/mapa")

    day = date.fromisoformat(day_iso)
    is_pre = (mode == "reserve")

    # valida regras EXCLUINDO o próprio item (pra não bloquear edição à toa)
    err = validate_mapa_rules(
        session,
        day,
        surgeon_id,
        procedure_type,
        uses_hsr=bool(uses_hsr),
        exclude_entry_id=entry_id,
    )
    if err:
        month = day.strftime("%Y-%m")
        from urllib.parse import quote
        return redirect(
            f"/mapa?month={month}&open=1&edit_id={entry_id}"
            f"&err={quote(err)}"
            f"&day_iso={quote(day_iso)}"
            f"&mode={quote(mode)}"
            f"&time_hhmm={quote(time_hhmm or '')}"
            f"&patient_name={quote(patient_name)}"
            f"&surgeon_id={surgeon_id}"
            f"&procedure_type={quote(procedure_type)}"
            f"&location={quote(location)}"
            f"&uses_hsr={1 if uses_hsr else 0}"
            f"&has_lodging={1 if has_lodging else 0}" 
        )

    # snapshot (opcional) pra auditoria
    before = {
        "day": row.day.isoformat(),
        "time_hhmm": row.time_hhmm,
        "patient_name": row.patient_name,
        "surgeon_id": row.surgeon_id,
        "procedure_type": row.procedure_type,
        "location": row.location,
        "uses_hsr": row.uses_hsr,
        "is_pre_reservation": row.is_pre_reservation,
    }

    time_hhmm = (time_hhmm or "").strip()  # normaliza

    # aplica alterações
    row.day = day
    row.time_hhmm = time_hhmm or None
    row.patient_name = patient_name.strip().upper()
    row.surgeon_id = surgeon_id
    row.procedure_type = procedure_type
    row.location = location
    row.uses_hsr = bool(uses_hsr)
    row.is_pre_reservation = is_pre
    row.created_by_id = seller_id_final 

    session.add(row)
    session.commit()

    audit_event(
        request,
        user,
        "surgical_map_updated",
        target_type="surgical_map",
        target_id=row.id,
        extra={
            "before": before,
            "after": {
                "day": row.day.isoformat(),
                "time_hhmm": row.time_hhmm,
                "patient_name": row.patient_name,
                "surgeon_id": row.surgeon_id,
                "procedure_type": row.procedure_type,
                "location": row.location,
                "uses_hsr": row.uses_hsr,
                "is_pre_reservation": row.is_pre_reservation,
            },
        },
    )

    month = day.strftime("%Y-%m")

    # ✅ Se marcou "Hospedagem", abre a tela de hospedagem depois de salvar
    if has_lodging:
        from urllib.parse import quote

        # regra padrão: check-in 2 dias após a cirurgia; check-out 1 dia depois (ajuste se quiser)
        check_in = (day + timedelta(days=2)).isoformat()
        check_out = (day + timedelta(days=3)).isoformat()

        return redirect(
            f"/hospedagem?month={month}&open=1"
            f"&unit="  # vazio (usuário escolhe suite/apto no modal)
            f"&check_in={quote(check_in)}"
            f"&check_out={quote(check_out)}"
            f"&patient_name={quote(patient_name.strip().upper())}"
            f"&is_pre_reservation={1 if is_pre else 0}"
        )

    return redirect(f"/mapa?month={month}")

@app.post("/mapa/delete/{entry_id}")
def mapa_delete(
    request: Request,
    entry_id: int,
    session: Session = Depends(get_session),
):
    user = get_current_user(request, session)
    if not user:
        return redirect("/login")
    require(user.role in ("admin", "surgery"))

    row = session.get(SurgicalMapEntry, entry_id)
    if row:
        month = row.day.strftime("%Y-%m")
        session.delete(row)
        session.commit()

        audit_event(
            request,
            user,
            "surgical_map_deleted",
            target_type="surgical_map",
            target_id=entry_id,
            extra={
                "day": row.day.isoformat(),
                "time_hhmm": row.time_hhmm,
                "patient_name": row.patient_name,
                "surgeon_id": row.surgeon_id,
                "procedure_type": row.procedure_type,
                "location": row.location,
                "uses_hsr": row.uses_hsr,
                "is_pre_reservation": getattr(row, "is_pre_reservation", None),
            },
        )
        return redirect(f"/mapa?month={month}")

    audit_event(
        request,
        user,
        "surgical_map_delete_not_found",
        success=False,
        message="Tentou apagar um agendamento que não existe (ou já foi removido).",
        target_type="surgical_map",
        target_id=entry_id,
    )
    return redirect("/mapa")

@app.get("/relatorio_gustavo", response_class=HTMLResponse)
def relatorio_gustavo_page(
    request: Request,
    snapshot_date: str = "",
    session: Session = Depends(get_session),
):
    user = get_current_user(request, session)
    if not user:
        return redirect("/login")
    require(user.username == "johnny.ge")

    snaps = session.exec(
        select(GustavoAgendaSnapshot).order_by(GustavoAgendaSnapshot.snapshot_date.desc())
    ).all()
    available_dates = [s.snapshot_date.isoformat() for s in snaps]

    selected = None
    if snapshot_date:
        try:
            y, m, d = map(int, snapshot_date.split("-"))
            sel = date(y, m, d)
            selected = session.exec(
                select(GustavoAgendaSnapshot).where(GustavoAgendaSnapshot.snapshot_date == sel)
            ).first()
        except Exception:
            selected = None
    today_sp = datetime.now(TZ).date()
    selected_keys = set(load_gustavo_selected_month_keys(today_sp))

    # opções: Jan..Dez do ano atual
    yy = today_sp.year
    pt_abbr = ["Jan", "Fev", "Mar", "Abr", "Mai", "Jun", "Jul", "Ago", "Set", "Out", "Nov", "Dez"]
    month_options = []
    for i in range(1, 13):
        key = f"{yy:04d}-{i:02d}"
        label = f"{pt_abbr[i-1]}/{str(yy)[2:]}"
        month_options.append({"key": key, "label": label})
        
    overrides = load_gustavo_overrides()

    return templates.TemplateResponse(
        "relatorio_gustavo.html",
        {
            "request": request,
            "current_user": user,
            "available_dates": available_dates,
            "snapshot": selected,
            "snapshot_date": snapshot_date or "",
            "month_options": month_options,
            "selected_months": selected_keys,
            "surgeons": GUSTAVO_REPORT_SURGEONS,
            "overrides": overrides,
        },
    )

@app.post("/relatorio_gustavo/config")
def relatorio_gustavo_save_config(
    request: Request,
    selected_months: list[str] = Form(default=[]),
    session: Session = Depends(get_session),
):
    user = get_current_user(request, session)
    if not user:
        return redirect("/login")
    require(user.username == "johnny.ge")

    # salva exatamente o que veio marcado (se vier vazio, cai no default na geração)
    keys = []
    for k in selected_months or []:
        if isinstance(k, str) and len(k) == 7 and k[4] == "-":
            keys.append(k)

    save_gustavo_selected_month_keys(keys)
    return redirect("/relatorio_gustavo")


@app.post("/relatorio_gustavo/override")
def relatorio_gustavo_save_override(
    request: Request,
    day_iso: str = Form(...),
    surgeon_username: str = Form(...),
    emoji: str = Form(...),
    reason: str = Form(default=""),
    session: Session = Depends(get_session),
):
    user = get_current_user(request, session)
    if not user:
        return redirect("/login")
    require(user.username == "johnny.ge")

    day_iso = (day_iso or "").strip()
    surgeon_username = (surgeon_username or "").strip()
    emoji = (emoji or "").strip()
    reason = (reason or "").strip()

    # valida data
    try:
        _ = date.fromisoformat(day_iso)
    except Exception:
        raise HTTPException(status_code=400, detail="Data inválida (use YYYY-MM-DD).")

    # valida médico (somente os 6 do relatório)
    allowed = {u for (u, _lbl) in GUSTAVO_REPORT_SURGEONS}
    if surgeon_username not in allowed:
        raise HTTPException(status_code=400, detail="Cirurgião inválido para override.")

    # valida emoji
    if emoji not in REPORT_EMOJIS:
        raise HTTPException(status_code=400, detail="Emoji inválido para override.")

    data = load_gustavo_overrides()
    data.setdefault(day_iso, {})
    data[day_iso][surgeon_username] = {
        "emoji": emoji,
        "reason": reason,
        "by": user.username,
        "at": datetime.utcnow().isoformat(),
    }
    save_gustavo_overrides(data)

    audit_logger.info(
        f"GUSTAVO_REPORT_OVERRIDE: day={day_iso} surgeon={surgeon_username} emoji={emoji} by={user.username}"
    )
    return redirect("/relatorio_gustavo")


@app.post("/relatorio_gustavo/override/delete")
def relatorio_gustavo_delete_override(
    request: Request,
    day_iso: str = Form(...),
    surgeon_username: str = Form(...),
    session: Session = Depends(get_session),
):
    user = get_current_user(request, session)
    if not user:
        return redirect("/login")
    require(user.username == "johnny.ge")

    day_iso = (day_iso or "").strip()
    surgeon_username = (surgeon_username or "").strip()

    data = load_gustavo_overrides()
    if day_iso in data and surgeon_username in (data.get(day_iso) or {}):
        data[day_iso].pop(surgeon_username, None)
        if not data[day_iso]:
            data.pop(day_iso, None)
        save_gustavo_overrides(data)

        audit_logger.info(
            f"GUSTAVO_REPORT_OVERRIDE_DELETE: day={day_iso} surgeon={surgeon_username} by={user.username}"
        )

    return redirect("/relatorio_gustavo")

@app.get("/relatorio_gustavo/preview", response_class=HTMLResponse)
def relatorio_gustavo_preview(
    request: Request,
    months: list[str] = Query(default=[]),
    session: Session = Depends(get_session),
):
    user = get_current_user(request, session)
    if not user:
        return redirect("/login")
    require(user.username == "johnny.ge")

    # ✅ gera na hora (não salva snapshot e não envia WhatsApp)
    today_sp = datetime.now(TZ).date()
    month_keys = months or None  # None => usa config salva (ou default)
    msg1, msg2, _payload = build_gustavo_whatsapp_messages(session, today_sp,month_keys=month_keys)

    preview_snapshot = SimpleNamespace(message_1=msg1, message_2=msg2)

    # mantém dropdown funcionando (com datas já salvas), mas exibe preview no corpo
    snaps = session.exec(
        select(GustavoAgendaSnapshot).order_by(GustavoAgendaSnapshot.snapshot_date.desc())
    ).all()
    available_dates = [s.snapshot_date.isoformat() for s in snaps]

    today_sp = datetime.now(TZ).date()

    # selecionados do preview: se veio query ?months=... usa ela; senão usa config salva
    selected_keys = set(months or load_gustavo_selected_month_keys(today_sp))

    yy = today_sp.year
    pt_abbr = ["Jan", "Fev", "Mar", "Abr", "Mai", "Jun", "Jul", "Ago", "Set", "Out", "Nov", "Dez"]
    month_options = []
    for i in range(1, 13):
        key = f"{yy:04d}-{i:02d}"
        label = f"{pt_abbr[i-1]}/{str(yy)[2:]}"
        month_options.append({"key": key, "label": label})

    overrides = load_gustavo_overrides()

    return templates.TemplateResponse(
        "relatorio_gustavo.html",
        {
            "request": request,
            "current_user": user,
            "available_dates": available_dates,
            "snapshot": preview_snapshot,
            "snapshot_date": "",  # não “seleciona” nenhuma data salva
            "month_options": month_options,
            "selected_months": selected_keys,
            "surgeons": GUSTAVO_REPORT_SURGEONS,
            "overrides": overrides,
        },
    )


@app.post("/relatorio_gustavo/run-now")
def relatorio_gustavo_run_now(
    request: Request,
    session: Session = Depends(get_session),
):
    user = get_current_user(request, session)
    if not user:
        return redirect("/login")

    # Somente admin ou surgery podem gerar manualmente
    require(user.username == "johnny.ge")

    # Data de hoje no fuso de SP
    now_sp = datetime.now(TZ)
    today_sp = now_sp.date()

    audit_logger.info(
        f"GUSTAVO_SNAPSHOT: geração manual solicitada por {user.username} em {today_sp}"
    )

    try:
        save_gustavo_snapshot_and_send(session, today_sp)
    except Exception as e:
        audit_logger.exception("Erro ao gerar snapshot manualmente")
        raise HTTPException(status_code=500, detail="Erro ao gerar snapshot")

    # Volta para a tela já selecionando a data gerada
    return redirect(f"/relatorio_gustavo?snapshot_date={today_sp.isoformat()}")

# ============================================================
# HOSPEDAGEM
# ============================================================

def normalize_unit(raw: Optional[str]) -> str:
    v = (raw or "").strip().lower()
    v = v.replace("suíte", "suite").replace("suíte", "suite")
    v = v.replace("-", " ").replace("_", " ")
    v = " ".join(v.split())  # colapsa múltiplos espaços

    if v in ("suite 1", "suite1", "suíte 1", "s1", "1", "01"):
        return "suite_1"
    if v in ("suite 2", "suite2", "suíte 2", "s2", "2", "02"):
        return "suite_2"
    if v in ("apto", "apt", "apartamento", "apartmento"):
        return "apto"

    # se já vier no padrão
    if v in ("suite_1", "suite_2", "apto"):
        return v

    return v

@app.get("/hospedagem", response_class=HTMLResponse)
def hospedagem_page(
    request: Request,
    month: Optional[str] = None,
    err: Optional[str] = None,
    open: Optional[str] = None,
    unit: Optional[str] = None,
    check_in: Optional[str] = None,
    check_out: Optional[str] = None,
    patient_name: Optional[str] = None,
    is_pre_reservation: Optional[str] = None,
    conflict_id: Optional[str] = None,
    note: Optional[str] = None,
    edit_id: Optional[str] = None,
    session: Session = Depends(get_session),
):
    user = get_current_user(request, session)
    if not user:
        return redirect("/login")
    allow_override = (user.username == "johnny.ge")

    conflict_obj = None
    if allow_override and conflict_id:
        try:
            cid = int(conflict_id)
            row = session.get(LodgingReservation, cid)
            if row:
                conflict_obj = {
                    "id": row.id,
                    "patient_name": row.patient_name,
                    "unit": row.unit,
                    "check_in": row.check_in.strftime("%d/%m/%Y"),
                    "check_out": row.check_out.strftime("%d/%m/%Y"),
                    "is_pre": 1 if row.is_pre_reservation else 0,
                }
        except Exception:
            conflict_obj = None

    require(user.role in ("admin", "surgery"))

    selected_month, first_day, next_month_first, days = safe_selected_month(month)
    # anos para o dropdown (ano atual até +5)
    years = list(range(first_day.year, first_day.year + 6))
    day_index = {d: i for i, d in enumerate(days)}

    units = ["suite_1", "suite_2", "apto"]

    audit_logger.info(
        f"HOSPEDAGEM_PAGE: selected_month={selected_month} "
        f"first_day={first_day} next_month_first={next_month_first}"
    )
    
    # busca reservas que encostam no mês (por período)
    q = select(LodgingReservation).where(
        LodgingReservation.check_in < next_month_first,
        LodgingReservation.check_out > first_day,
    )
    reservations = session.exec(q).all()

    # pré-carrega usuários criadores (para exibir no template)
    creator_ids = list({getattr(r, "created_by_id", None) for r in reservations if getattr(r, "created_by_id", None)})
    users_by_id: dict[int, User] = {}
    if creator_ids:
        users = session.exec(select(User).where(User.id.in_(creator_ids))).all()
        users_by_id = {u.id: u for u in users if u.id is not None}

    # barras por unidade (grid com colunas = dias)
    bars_by_unit: dict[str, list[dict]] = {u: [] for u in units}

    for r in reservations:
        u = normalize_unit(getattr(r, "unit", None))
        if u not in bars_by_unit:
            audit_logger.warning(f"HOSPEDAGEM_PAGE: unit_desconhecida_no_db id={r.id} unit={getattr(r,'unit',None)}")
            continue

        # clamp dentro do mês visível
        start = max(r.check_in, first_day)
        end = min(r.check_out, next_month_first)
        if start >= end:
            continue

        start_col = (start - first_day).days + 2
        end_col = (end - first_day).days + 2
        if end_col <= start_col:
            continue

        # resolve creator (robusto)
        creator_username = ""
        cid = getattr(r, "created_by_id", None)
        if isinstance(cid, str) and cid.isdigit():
            cid = int(cid)

        if cid is not None and cid in users_by_id:
            creator_username = users_by_id[cid].username or ""

        created_at_str = ""
        created_at = getattr(r, "created_at", None)
        if created_at:
            try:
                created_at_str = created_at.strftime("%d/%m/%Y %H:%M")
            except Exception:
                created_at_str = str(created_at)

        bars_by_unit[u].append(
            {
                "id": r.id,
                "patient_name": r.patient_name,
                "check_in": r.check_in.strftime("%d/%m/%Y"),
                "check_out": r.check_out.strftime("%d/%m/%Y"),
                "start_col": start_col,
                "end_col": end_col,
                "is_pre": 1 if r.is_pre_reservation else 0,
                "note": getattr(r, "note", "") or "",
                "created_by_username": creator_username,
                "created_at_str": created_at_str,
            }
        )

    # ✅ lista para exibir "Reservas do mês" abaixo do quadro
    reservations_list = []
    for r in reservations:
        u = normalize_unit(getattr(r, "unit", None))
        if u not in ("suite_1", "suite_2", "apto"):
            continue

        created_by_username = ""
        cid = getattr(r, "created_by_id", None)
        if isinstance(cid, str) and cid.isdigit():
            cid = int(cid)

        if cid is not None and cid in users_by_id:
            created_by_username = users_by_id[cid].username or ""

        created_at_str = ""
        created_at = getattr(r, "created_at", None)
        if created_at:
            try:
                created_at_str = created_at.strftime("%d/%m/%Y %H:%M")
            except Exception:
                created_at_str = str(created_at)

        reservations_list.append(
            {
                "id": r.id,
                "unit": u,
                "unit_label": human_unit(u),
                "patient_name": r.patient_name or "",
                "check_in": r.check_in.strftime("%d/%m/%Y"),
                "check_out": r.check_out.strftime("%d/%m/%Y"),
                "is_pre": 1 if r.is_pre_reservation else 0,
                "note": getattr(r, "note", "") or "",
                "created_by_username": created_by_username,
                "created_at_str": created_at_str,
            }
        )

    reservations_list.sort(key=lambda x: (x["check_in"], x["unit"], x["patient_name"]))

    audit_logger.info(f"HOSPEDAGEM_PAGE: reservations_found={len(reservations)}")
    if reservations:
        audit_logger.info(
            "HOSPEDAGEM_PAGE_SAMPLE: " +
            " | ".join([
                f"id={r.id},unit={r.unit},ci={r.check_in},co={r.check_out}"
                for r in reservations[:5]
            ])
        )
    
    # barras por unidade (grid com colunas = dias)
    bars_by_unit: dict[str, list[dict]] = {u: [] for u in units}

    # lista do mês (para exibir abaixo do grid)
    month_reservations = []
    for r in reservations:
        u = normalize_unit(getattr(r, "unit", None))
        if u not in ("suite_1", "suite_2", "apto"):
            continue

        creator_username = ""
        if getattr(r, "created_by_id", None) in users_by_id:
            creator_username = users_by_id[r.created_by_id].username or ""

        created_at_str = ""
        created_at = getattr(r, "created_at", None)
        if created_at:
            try:
                created_at_str = datetime.fromtimestamp(created_at.timestamp(), TZ).strftime("%d/%m/%Y %H:%M")
            except Exception:
                created_at_str = created_at.strftime("%d/%m/%Y %H:%M")

        month_reservations.append({
            "id": r.id,
            "unit": u,
            "unit_label": human_unit(u),
            "patient_name": r.patient_name,
            "check_in": r.check_in.strftime("%d/%m/%Y"),
            "check_out": r.check_out.strftime("%d/%m/%Y"),
            "is_pre": 1 if r.is_pre_reservation else 0,
            "note": getattr(r, "note", "") or "",
            "created_by": creator_username,
            "created_at": created_at_str,
        })

    month_reservations.sort(key=lambda x: (x["check_in"], x["unit"]))

    # pré-carrega usuários criadores (para exibir no template)
    creator_ids = list({r.created_by_id for r in reservations if getattr(r, "created_by_id", None)})
    users_by_id: dict[int, User] = {}
    if creator_ids:
        users = session.exec(select(User).where(User.id.in_(creator_ids))).all()
        users_by_id = {u.id: u for u in users if u.id is not None}

    for r in reservations:
        u = normalize_unit(getattr(r, "unit", None))
        if u not in bars_by_unit:
            # loga pra você enxergar se aparecer algum valor novo inesperado
            audit_logger.warning(f"HOSPEDAGEM_PAGE: unit_desconhecida_no_db id={r.id} unit={getattr(r,'unit',None)}")
            continue

        # clamp dentro do mês visível
        start = max(r.check_in, first_day)
        end = min(r.check_out, next_month_first)
        if start >= end:
            continue

        start_col = (start - first_day).days + 2
        end_col = (end - first_day).days + 2
        if end_col <= start_col:
            continue

        creator_username = ""
        if getattr(r, "created_by_id", None) in users_by_id:
            creator_username = users_by_id[r.created_by_id].username or ""

        created_at_str = ""
        created_at = getattr(r, "created_at", None)
        if created_at:
            # se você já usa TZ no projeto, mantém padrão (SP)
            try:
                created_at_str = datetime.fromtimestamp(created_at.timestamp(), TZ).strftime("%d/%m/%Y %H:%M")
            except Exception:
                created_at_str = created_at.strftime("%d/%m/%Y %H:%M")

        bars_by_unit[u].append(
            {
                "id": r.id,
                "patient_name": r.patient_name,
                "check_in": r.check_in.strftime("%d/%m/%Y"),
                "check_out": r.check_out.strftime("%d/%m/%Y"),
                "start_col": start_col,
                "end_col": end_col,
                "is_pre": 1 if r.is_pre_reservation else 0,

                # ✅ novos campos (seu template já tenta usar note/created_by)
                "note": getattr(r, "note", "") or "",
                "created_by_id": getattr(r, "created_by_id", None),
                "created_by_username": creator_username,
                "created_at": created_at_str,
            }
        )
    # ✅ lista para exibir "Reservas do mês" abaixo do quadro
    reservations_list = []
    for r in reservations:
        u = normalize_unit(getattr(r, "unit", None))
        if u not in ("suite_1", "suite_2", "apto"):
            continue

        created_by_username = ""
        cid = getattr(r, "created_by_id", None)
        if cid is not None and cid in users_by_id:
            created_by_username = users_by_id[cid].username or ""

        created_at_str = ""
        created_at = getattr(r, "created_at", None)
        if created_at:
            # created_at costuma ser datetime
            try:
                created_at_str = created_at.strftime("%d/%m/%Y %H:%M")
            except Exception:
                created_at_str = str(created_at)

        reservations_list.append(
            {
                "id": r.id,
                "unit": u,
                "patient_name": r.patient_name or "",
                "check_in_br": r.check_in.strftime("%d/%m/%Y"),
                "check_out_br": r.check_out.strftime("%d/%m/%Y"),
                "is_pre": 1 if r.is_pre_reservation else 0,
                "note": (getattr(r, "note", "") or ""),
                "created_by_username": created_by_username,
                "created_at_str": created_at_str,
            }
        )

    reservations_list.sort(key=lambda x: (x["check_in_br"], x["unit"], x["patient_name"]))


    # ordena barras na linha
    for u in bars_by_unit:
        bars_by_unit[u].sort(key=lambda b: (b["start_col"], b["end_col"]))

    
    prefill = {
        "unit": unit or "",
        "check_in": check_in or "",
        "check_out": check_out or "",
        "patient_name": patient_name or "",
        "is_pre_reservation": 1 if (is_pre_reservation == "1") else 0,
        "edit_id": edit_id or "",
    }
    
    # ✅ lista do mês (abaixo do grid)
    reservations_list = []
    for r in reservations:
        # só mostrar as que encostam no mês visível (mesma lógica do grid)
        start = max(r.check_in, first_day)
        end = min(r.check_out, next_month_first)
        if start >= end:
            continue

        created_by_username = ""
        cid = getattr(r, "created_by_id", None)
        if cid in users_by_id:
            created_by_username = users_by_id[cid].username or ""

        created_at_str = ""
        created_at = getattr(r, "created_at", None) or getattr(r, "created_at_dt", None)
        if created_at:
            try:
                # se vier datetime
                if hasattr(created_at, "astimezone"):
                    created_at_str = created_at.astimezone(TZ).strftime("%d/%m/%Y %H:%M")
                else:
                    created_at_str = str(created_at)
            except Exception:
                created_at_str = str(created_at)

        reservations_list.append({
            "id": r.id,
            "unit": normalize_unit(getattr(r, "unit", None)),
            "patient_name": (r.patient_name or "").strip(),
            "check_in_br": r.check_in.strftime("%d/%m/%Y"),
            "check_out_br": r.check_out.strftime("%d/%m/%Y"),
            "is_pre": 1 if getattr(r, "is_pre_reservation", False) else 0,
            "note": getattr(r, "note", None) or "",
            "created_by_username": created_by_username,
            "created_at_str": created_at_str,
        })

    # ordena por data
    reservations_list.sort(key=lambda x: (x["check_in_br"], x["check_out_br"], x["unit"], x["patient_name"]))

    
    return templates.TemplateResponse(
        "hospedagem.html",
        {
            "request": request,
            "current_user": user,
            "selected_month": selected_month,
            "days": days,
            "years": years,
            "units": units,
            "bars_by_unit": bars_by_unit,
            "reservations_list": reservations_list,
            "human_unit": human_unit,
            "err": err or "",
            "open": open or "",

            # mantém o que você já tinha (pode continuar usando no template, se quiser)
            "unit_prefill": unit or "",
            "check_in_prefill": check_in or "",
            "check_out_prefill": check_out or "",
            "patient_prefill": patient_name or "",
            "pre_prefill": 1 if (is_pre_reservation == "1") else 0,
            "edit_id": edit_id or "",
            
            "allow_override": allow_override,

            "conflict": conflict_obj,

            "prefill_note": note or "",

            # ✅ ADICIONE ISTO (para o template não quebrar com prefill.unit)
            "prefill": {
                "unit": unit or "",
                "check_in": check_in or "",
                "check_out": check_out or "",
                "patient_name": patient_name or "",
                "is_pre_reservation": 1 if (is_pre_reservation == "1") else 0,
            },
        },
    )

@app.post("/hospedagem/create")
def hospedagem_create(
    request: Request,
    month: str = Form(""),
    unit: str = Form(...),
    patient_name: str = Form(...),
    check_in: str = Form(...),
    check_out: str = Form(...),
    is_pre_reservation: Optional[str] = Form(None),
    note: Optional[str] = Form(None),
    surgery_entry_id: Optional[int] = Form(None),
    session: Session = Depends(get_session),
):
    user = get_current_user(request, session)
    if not user:
        return redirect("/login")
    require(user.role in ("admin", "surgery"))

    try:
        ci = date.fromisoformat(check_in)
        co = date.fromisoformat(check_out)
    except Exception:
        return redirect(f"/hospedagem?err={quote('Datas inválidas.')}&open=1")

    e = validate_lodging_period(ci, co)
    if e:
        return redirect(f"/hospedagem?err={quote(e)}&open=1")

    e = validate_lodging_conflict(session, unit, ci, co)
    if e:
        month_param = (month or "").strip() or f"{ci.year:04d}-{ci.month:02d}"

        # ✅ somente o johnny.ge pode "ver o conflito" e optar por sobrepor
        if user.username == "johnny.ge":
            conflict = get_lodging_conflict_row(session, unit, ci, co)
            conflict_id = conflict.id if conflict else ""

            return redirect(
                f"/hospedagem?month={quote(month_param)}&open=1"
                f"&err={quote(e)}"
                f"&conflict_id={conflict_id}"
                f"&unit={quote(unit)}&check_in={quote(check_in)}&check_out={quote(check_out)}"
                f"&patient_name={quote(patient_name)}&is_pre_reservation={(1 if is_pre_reservation else 0)}"
                f"&note={quote(note or '')}"
                f"&surgery_entry_id={surgery_entry_id or ''}"
            )

        # demais usuários: mantém o bloqueio (sem permissão)
        return redirect(
            f"/hospedagem?month={quote(month_param)}&open=1"
            f"&err={quote(e)}"
            f"&unit={quote(unit)}&check_in={quote(check_in)}&check_out={quote(check_out)}"
            f"&patient_name={quote(patient_name)}&is_pre_reservation={(1 if is_pre_reservation else 0)}"
            f"&note={quote(note or '')}"
            f"&surgery_entry_id={surgery_entry_id or ''}"
        )

    row = LodgingReservation(
        unit=normalize_unit(unit),
        patient_name=patient_name.strip().upper(),
        check_in=ci,
        check_out=co,
        is_pre_reservation=bool(is_pre_reservation),
        note=(note or None),
        created_by_id=user.id,
        updated_by_id=user.id,
        surgery_entry_id=surgery_entry_id,
    )
    session.add(row)
    session.commit()

    audit_event(
        request,
        user,
        action="lodging_create",
        success=True,
        message=None,
        target_type="lodging",
        target_id=row.id,
    )

    audit_logger.info(
        f"HOSPEDAGEM_CREATE: id={row.id} unit={row.unit} "
        f"ci={row.check_in} co={row.check_out} patient={row.patient_name}"
    )
 
    month_param = (month or "").strip() or f"{ci.year:04d}-{ci.month:02d}"
    return redirect(f"/hospedagem?month={month_param}")

@app.post("/hospedagem/override")
def hospedagem_override(
    request: Request,
    month: str = Form(""),
    conflict_id: int = Form(...),

    unit: str = Form(...),
    patient_name: str = Form(...),
    check_in: str = Form(...),
    check_out: str = Form(...),
    is_pre_reservation: Optional[str] = Form(None),
    note: Optional[str] = Form(None),
    surgery_entry_id: Optional[str] = Form(None),

    session: Session = Depends(get_session),
):
    user = get_current_user(request, session)
    if not user:
        return redirect("/login")

    # ✅ bloqueio TOTAL: só johnny.ge pode sobrepor
    require(user.username == "johnny.ge")

    # parse datas
    try:
        ci = date.fromisoformat(check_in)
        co = date.fromisoformat(check_out)
    except Exception:
        return redirect(f"/hospedagem?err={quote('Datas inválidas')}&open=1")

    # pega a reserva conflitante
    old = session.get(LodgingReservation, conflict_id)
    if not old:
        return redirect(f"/hospedagem?err={quote('Reserva conflitante não encontrada')}&open=1")

    # remove a antiga
    session.delete(old)
    session.commit()

    # valida novamente (caso exista outra reserva além da que foi apagada)
    e = validate_lodging_conflict(session, unit, ci, co)
    if e:
        month_param = (month or "").strip() or f"{ci.year:04d}-{ci.month:02d}"
        return redirect(
            f"/hospedagem?month={quote(month_param)}&open=1"
            f"&err={quote(e)}"
            f"&unit={quote(unit)}&check_in={quote(check_in)}&check_out={quote(check_out)}"
            f"&patient_name={quote(patient_name)}&is_pre_reservation={(1 if is_pre_reservation else 0)}"
            f"&note={quote(note or '')}"
            f"&surgery_entry_id={surgery_entry_id or ''}"
        )
    surgery_entry_id_int: Optional[int] = None
    if surgery_entry_id is not None:
        s = str(surgery_entry_id).strip()
        if s.isdigit():
            surgery_entry_id_int = int(s)
            
    # cria a nova
    row = LodgingReservation(
        unit=unit,
        patient_name=patient_name,
        check_in=ci,
        check_out=co,
        is_pre_reservation=bool(is_pre_reservation),
        note=(note or "").strip() or None,
        surgery_entry_id=surgery_entry_id_int,
    )
    session.add(row)
    session.commit()
    session.refresh(row)

    audit_logger.info(
        f"HOSPEDAGEM_OVERRIDE: deleted_id={conflict_id} | new_id={row.id} unit={row.unit} ci={row.check_in} co={row.check_out} patient={row.patient_name}"
    )

    month_param = (month or "").strip() or f"{ci.year:04d}-{ci.month:02d}"
    return redirect(f"/hospedagem?month={month_param}")

@app.post("/hospedagem/update/{res_id}")
def hospedagem_update(
    request: Request,
    res_id: int,
    unit: str = Form(...),
    patient_name: str = Form(...),
    check_in: str = Form(...),
    check_out: str = Form(...),
    is_pre_reservation: Optional[str] = Form(None),
    note: Optional[str] = Form(None),
    session: Session = Depends(get_session),
):
    user = get_current_user(request, session)
    if not user:
        return redirect("/login")
    require(user.role in ("admin", "surgery"))

    row = session.get(LodgingReservation, res_id)
    if not row:
        raise HTTPException(status_code=404, detail="Reserva não encontrada")

    try:
        ci = date.fromisoformat(check_in)
        co = date.fromisoformat(check_out)
    except Exception:
        return redirect(f"/hospedagem?err={quote('Datas inválidas.')}&open=1")

    e = validate_lodging_period(ci, co)
    if e:
        return redirect(f"/hospedagem?err={quote(e)}&open=1&edit_id={res_id}")

    e = validate_lodging_conflict(session, unit, ci, co, exclude_id=res_id)
    if e:
        return redirect(f"/hospedagem?err={quote(e)}&open=1&edit_id={res_id}")

    row.unit = unit
    row.patient_name = patient_name.strip().upper()
    row.check_in = ci
    row.check_out = co
    row.is_pre_reservation = bool(is_pre_reservation)
    row.note = (note or None)
    row.updated_by_id = user.id
    row.updated_at = datetime.utcnow()

    session.add(row)
    session.commit()

    audit_event(
        request,
        user,
        action="lodging_update",
        success=True,
        message=None,
        target_type="lodging",
        target_id=row.id,
    )

    month_param = f"{ci.year:04d}-{ci.month:02d}"
    return redirect(f"/hospedagem?month={month_param}")


@app.post("/hospedagem/delete/{res_id}")
def hospedagem_delete(
    request: Request,
    res_id: int,
    session: Session = Depends(get_session),
):
    user = get_current_user(request, session)
    if not user:
        return redirect("/login")
    require(user.role in ("admin", "surgery"))

    row = session.get(LodgingReservation, res_id)
    if not row:
        return redirect("/hospedagem")

    month_param = f"{row.check_in.year:04d}-{row.check_in.month:02d}"

    session.delete(row)
    session.commit()

    audit_event(
        request,
        user,
        action="lodging_delete",
        success=True,
        message=None,
        target_type="lodging",
        target_id=res_id,
    )
    return redirect(f"/hospedagem?month={month_param}")
