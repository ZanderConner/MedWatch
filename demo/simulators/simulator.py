#!/usr/bin/env python3
"""
DICOM Modality Simulator
Sends real DICOM files (TCIA) or viewable synthetic images via C-STORE
to a target Orthanc server. Runs a C-ECHO SCP on a separate AE instance
so Orthanc can ping it green without interfering with outbound sends.

Startup sequence
────────────────
1. Start DICOM SCP (separate AE) on DICOM_LISTEN_PORT for C-ECHO responses.
2. Wait up to TCIA_WAIT_MINUTES for /tcia_data/.loaded sentinel.
3. Scan for MODALITY-compatible files; fallback to synthetic same-modality data.
4. Enter send loop respecting WORK_HOURS and JITTER settings.
"""

from __future__ import annotations

import csv
import datetime
import json
import logging
import os
import pathlib
import random
import sys
import threading
import time
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import numpy as np
import pydicom
import pydicom.uid as uid_mod
from pydicom.dataset import FileDataset, FileMetaDataset
from pynetdicom import AE, StoragePresentationContexts, evt
from pynetdicom.sop_class import (
    ComputedRadiographyImageStorage,
    CTImageStorage,
    DigitalXRayImageStorageForPresentation,
    MRImageStorage,
    NuclearMedicineImageStorage,
    Verification,
)

# ── Structured JSON logger ────────────────────────────────────

_RECORD_BUILTINS = frozenset(logging.LogRecord("", 0, "", 0, "", (), None).__dict__)


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        out: dict[str, Any] = {
            "timestamp": datetime.datetime.now(datetime.UTC)
                             .isoformat(timespec="milliseconds")
                             .replace("+00:00", "Z"),
            "level":   record.levelname,
            "logger":  record.name,
            "message": record.getMessage(),
        }
        for k, v in record.__dict__.items():
            if k not in _RECORD_BUILTINS and not k.startswith("_"):
                out[k] = v
        return json.dumps(out)


_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(_JsonFormatter())
log = logging.getLogger("modality-sim")
log.addHandler(_handler)
log.setLevel(logging.INFO)
log.propagate = False


def _log(level: int, msg: str, **fields: Any) -> None:
    log.log(level, msg, extra=fields)

def _info(msg: str,    **f: Any) -> None: _log(logging.INFO,    msg, **f)
def _warning(msg: str, **f: Any) -> None: _log(logging.WARNING, msg, **f)
def _error(msg: str,   **f: Any) -> None: _log(logging.ERROR,   msg, **f)
def _debug(msg: str,   **f: Any) -> None: _log(logging.DEBUG,   msg, **f)


# ── Configuration ─────────────────────────────────────────────

def _env_int(key: str, default: int) -> int:
    try:
        return int(os.environ[key])
    except (KeyError, ValueError):
        return default

def _parse_hhmm(value: str) -> datetime.time:
    parts = value.strip().split(":")
    if len(parts) != 2:
        raise ValueError(f"Expected HH:MM, got {value!r}")
    return datetime.time(int(parts[0]), int(parts[1]))

def _load_timezone(tz_name: str) -> ZoneInfo:
    try:
        return ZoneInfo(tz_name)
    except ZoneInfoNotFoundError:
        _warning("Unknown timezone — falling back to UTC", bad_tz=tz_name)
        return ZoneInfo("UTC")

REQUESTED_MODALITY = os.getenv("MODALITY", "CT").strip().upper()
DEVICE_MODALITY_LABEL = os.getenv("DEVICE_MODALITY_LABEL", REQUESTED_MODALITY).strip().upper()
AET               = os.getenv("AET", "SIM_AET")
TARGET_HOST       = os.getenv("TARGET_HOST", "172.20.2.10")
TARGET_PORT       = _env_int("TARGET_PORT", 11112)
TARGET_AET        = os.getenv("TARGET_AET", "DICOM_PRIMARY")
TCIA_DATA_DIR     = pathlib.Path(os.getenv("TCIA_DATA_DIR", "/tcia_data"))
PATIENT_POOL_CSV  = pathlib.Path(os.getenv("PATIENT_POOL_CSV", "/app/patients.csv"))
STUDIES_PER_BURST = _env_int("STUDIES_PER_BURST", 1)
DICOM_LISTEN_PORT = _env_int("DICOM_LISTEN_PORT", 11112)

SEND_INTERVAL     = _env_int("SEND_INTERVAL", 60)
JITTER_MIN        = _env_int("JITTER_MIN_SECONDS", 5)
JITTER_MAX        = _env_int("JITTER_MAX_SECONDS", 30)
TCIA_WAIT_MINUTES = _env_int("TCIA_WAIT_MINUTES", 10)
ACCESSION_PREFIX  = os.getenv("ACCESSION_PREFIX", "AUMC").strip().upper()
HOSPITAL_NAME     = os.getenv("HOSPITAL_NAME", "AU Medical Center").strip() or "AU Medical Center"
HOSPITAL_ADDRESS  = os.getenv("HOSPITAL_ADDRESS", "1120 15th St, Augusta, GA 30912").strip()
SIM_STUDY_END_DATE = os.getenv("SIM_STUDY_END_DATE", "").strip()

_raw_start = os.getenv("WORK_HOURS_START", "07:00")
_raw_end   = os.getenv("WORK_HOURS_END",   "18:00")
WORK_START = _parse_hhmm(_raw_start)
WORK_END   = _parse_hhmm(_raw_end)
TZ         = _load_timezone(os.getenv("TZ", "UTC"))
ALWAYS_ON  = (WORK_START == datetime.time(0, 0) and WORK_END == datetime.time(0, 0))

TCIA_SENTINEL = TCIA_DATA_DIR / ".loaded"
_STUDY_META_BY_UID: dict[str, dict[str, str | int]] = {}
_SYNTHETIC_SEQUENCE = 0
_STUDY_META_LOCK = threading.Lock()

_MODALITY_ALIASES: dict[str, str] = {
    "MRI": "MR",
    "X-RAY": "CR",
    "XRAY": "CR",
    "XR": "CR",
}
MODALITY = _MODALITY_ALIASES.get(REQUESTED_MODALITY, REQUESTED_MODALITY)

_ACCEPTED_DICOM_MODALITIES: dict[str, set[str]] = {
    "MR": {"MR"},
    "CR": {"CR", "DX", "XR"},
}

MODALITY_SOP_MAP: dict[str, str] = {
    "MR":  MRImageStorage,
    "MRI": MRImageStorage,
    "CT":  CTImageStorage,
    "CR":  ComputedRadiographyImageStorage,
    "DX":  DigitalXRayImageStorageForPresentation,
    "XR":  DigitalXRayImageStorageForPresentation,
    "NM":  NuclearMedicineImageStorage,
}
PRIMARY_SOP = MODALITY_SOP_MAP.get(MODALITY, CTImageStorage)

STUDY_DESCRIPTIONS = {
    "CT":  "CT Chest Without Contrast",
    "MR":  "MRI Brain Without Contrast",
    "MRI": "MRI Brain Without Contrast",
    "CR":  "PA and Lateral Chest",
    "DX":  "PA and Lateral Chest",
    "XR":  "PA and Lateral Chest",
    "NM":  "Tc-99m Bone Scan Whole Body",
}

PatientRecord = tuple[str, str, str, str, str]

# Emergency fallback if the external CSV is not mounted or has no valid rows.
# Normal range data lives in patient_pool.csv so teams can extend it without
# changing simulator code.
_FALLBACK_PATIENT_POOL: list[PatientRecord] = [
    ("MORALES^CHRISTOPHER", "19961228", "M", "MRN10042", "PATEL^PRIYA^DR"),
    ("SMITH^MICHAEL", "19541023", "M", "MRN10043", "GARCIA^LUIS^DR"),
    ("BREWER^WILLIAM^S", "19410518", "M", "MRN10044", "CHEN^WEI^DR"),
    ("SANDOVAL^DIANA", "19591010", "F", "MRN10046", "PATEL^PRIYA^DR"),
    ("GARCIA^DEREK", "19910611", "M", "MRN10047", "GARCIA^LUIS^DR"),
]


def _valid_dicom_date(value: str) -> bool:
    try:
        datetime.datetime.strptime(value, "%Y%m%d")
        return True
    except ValueError:
        return False


def _load_patient_pool(path: pathlib.Path) -> list[PatientRecord]:
    required = ("patient_name", "birth_date", "sex", "patient_id", "referring_physician")
    if not path.exists():
        _warning(
            "Patient pool CSV not found — using fallback pool",
            path=str(path),
            fallback_records=len(_FALLBACK_PATIENT_POOL),
        )
        return list(_FALLBACK_PATIENT_POOL)

    records: list[PatientRecord] = []
    skipped = 0
    try:
        with path.open(newline="", encoding="utf-8-sig") as handle:
            reader = csv.DictReader(handle)
            missing = [field for field in required if field not in (reader.fieldnames or [])]
            if missing:
                _warning(
                    "Patient pool CSV missing required columns — using fallback pool",
                    path=str(path),
                    missing_columns=missing,
                    fallback_records=len(_FALLBACK_PATIENT_POOL),
                )
                return list(_FALLBACK_PATIENT_POOL)

            for row_num, row in enumerate(reader, start=2):
                patient_name = (row.get("patient_name") or "").strip()
                birth_date = (row.get("birth_date") or "").strip()
                sex = (row.get("sex") or "").strip().upper()
                patient_id = (row.get("patient_id") or "").strip()
                physician = (row.get("referring_physician") or "").strip()

                if (
                    not patient_name
                    or not _valid_dicom_date(birth_date)
                    or sex not in {"M", "F", "O", "U"}
                    or not patient_id
                    or not physician
                ):
                    skipped += 1
                    _warning(
                        "Skipping invalid patient pool row",
                        path=str(path),
                        row=row_num,
                        patient_name=patient_name,
                        birth_date=birth_date,
                        sex=sex,
                        patient_id=patient_id,
                    )
                    continue

                records.append((patient_name, birth_date, sex, patient_id, physician))

    except Exception as exc:
        _warning(
            "Patient pool CSV could not be read — using fallback pool",
            path=str(path),
            error=str(exc),
            fallback_records=len(_FALLBACK_PATIENT_POOL),
        )
        return list(_FALLBACK_PATIENT_POOL)

    if not records:
        _warning(
            "Patient pool CSV had no valid rows — using fallback pool",
            path=str(path),
            skipped_rows=skipped,
            fallback_records=len(_FALLBACK_PATIENT_POOL),
        )
        return list(_FALLBACK_PATIENT_POOL)

    _info("Patient pool loaded", path=str(path), records=len(records), skipped_rows=skipped)
    return records


_PATIENT_POOL = _load_patient_pool(pathlib.Path("/app/patients.csv"))


def _stamp_phi(
    ds: pydicom.Dataset,
    study_uid: str,
    operational_meta: dict[str, str | int] | None = None,
) -> pydicom.Dataset:
    """
    Re-stamp realistic synthetic PHI onto a de-identified TCIA dataset.

    TCIA strips all patient identifiers before publishing.  For the HIPAA
    range we need visible PHI so Orthanc displays patient names, DOBs, etc.
    and so students can observe PHI flowing in cleartext DICOM.

    Patient assignment is deterministic per StudyInstanceUID so every
    file in the same study gets the same patient — Orthanc groups them
    correctly.  Different studies get different patients.
    """
    import hashlib as _hl
    # Deterministic index: hash the study UID → consistent patient per study
    idx = int(_hl.md5(study_uid.encode()).hexdigest(), 16) % len(_PATIENT_POOL)
    name, dob, sex, mrn, physician = _PATIENT_POOL[idx]

    now = datetime.datetime.now(datetime.UTC)

    # ── Patient module ────────────────────────────────────────
    ds.PatientName          = name
    ds.PatientID            = mrn
    ds.PatientBirthDate     = dob
    ds.PatientSex           = sex
    ds.PatientAge           = f"{(now.year - int(dob[:4])):03d}Y"

    # ── General study module ──────────────────────────────────
    ds.ReferringPhysicianName = physician
    ds.InstitutionName        = HOSPITAL_NAME
    if HOSPITAL_ADDRESS:
        ds.InstitutionAddress = HOSPITAL_ADDRESS
    ds.StationName            = AET

    # Replace source operational identifiers with synthetic but realistic values.
    ds = _apply_operational_metadata(ds, study_uid, operational_meta)

    # Study description from our map if blank
    if not getattr(ds, "StudyDescription", None):
        mod = getattr(ds, "Modality", MODALITY)
        ds.StudyDescription = STUDY_DESCRIPTIONS.get(mod, "Imaging Study")

    return ds


# ── Working-hours ─────────────────────────────────────────────

def _now_local() -> datetime.datetime:
    return datetime.datetime.now(tz=TZ)

def is_within_working_hours() -> bool:
    if ALWAYS_ON:
        return True
    now_t = _now_local().time().replace(second=0, microsecond=0)
    if WORK_START <= WORK_END:
        return WORK_START <= now_t < WORK_END
    return now_t >= WORK_START or now_t < WORK_END

def seconds_until_work_start() -> float:
    now_dt = _now_local()
    start  = now_dt.replace(
        hour=WORK_START.hour, minute=WORK_START.minute, second=0, microsecond=0
    )
    if start <= now_dt:
        start += datetime.timedelta(days=1)
    return (start - now_dt).total_seconds()


# ── Jitter ────────────────────────────────────────────────────

def jittered_interval() -> float:
    if JITTER_MIN == 0 and JITTER_MAX == 0:
        return float(SEND_INTERVAL)
    return max(1.0, SEND_INTERVAL + random.choice([-1, 1]) * random.uniform(JITTER_MIN, JITTER_MAX))


# ── Study metadata normalization ───────────────────────────────

def _parse_dicom_date(value: Any) -> datetime.date | None:
    text = str(value or "").strip()
    if len(text) < 8:
        return None
    try:
        return datetime.datetime.strptime(text[:8], "%Y%m%d").date()
    except ValueError:
        return None


def _parse_dicom_time(value: Any) -> str | None:
    digits = "".join(ch for ch in str(value or "") if ch.isdigit())
    if len(digits) < 4:
        return None
    hh = int(digits[0:2])
    mm = int(digits[2:4])
    ss = int(digits[4:6] if len(digits) >= 6 else "00")
    if hh > 23 or mm > 59 or ss > 59:
        return None
    return f"{hh:02d}{mm:02d}{ss:02d}"


def _study_end_date() -> datetime.date:
    if SIM_STUDY_END_DATE:
        for fmt in ("%Y%m%d", "%Y-%m-%d"):
            try:
                return datetime.datetime.strptime(SIM_STUDY_END_DATE, fmt).date()
            except ValueError:
                pass
        _warning("Invalid SIM_STUDY_END_DATE — using current date", value=SIM_STUDY_END_DATE)
    return _now_local().date()


def _sequence_time(sequence: int) -> str:
    base = datetime.datetime.combine(datetime.date(2000, 1, 1), datetime.time(7, 30))
    # Seventeen minutes gives realistic ordering without looking metronomic.
    shifted = base + datetime.timedelta(minutes=((sequence - 1) * 17) % (12 * 60))
    return shifted.strftime("%H%M%S")


def _accession_for(fake_date: datetime.date, sequence: int) -> str:
    prefix = "".join(ch for ch in ACCESSION_PREFIX if ch.isalnum())[:6] or "AUMC"
    return f"{prefix}{fake_date:%Y%m%d}{sequence:04d}"


def _first_study_datetime(files: list[pathlib.Path]) -> tuple[datetime.date | None, str | None]:
    for path in files:
        try:
            ds = pydicom.dcmread(str(path), stop_before_pixels=True)
            return _parse_dicom_date(getattr(ds, "StudyDate", None)), _parse_dicom_time(getattr(ds, "StudyTime", None))
        except Exception:
            continue
    return None, None


def _build_study_metadata(studies: dict[str, list[pathlib.Path]]) -> None:
    records: list[tuple[datetime.date, str, str]] = []
    for study_uid, files in studies.items():
        src_date, src_time = _first_study_datetime(files)
        records.append((
            src_date or datetime.date(1900, 1, 1),
            src_time or "000000",
            study_uid,
        ))

    records.sort()
    end_date = _study_end_date()
    total = len(records)
    metadata: dict[str, dict[str, str | int]] = {}

    for sequence, (_src_date, _src_time, study_uid) in enumerate(records, start=1):
        fake_date = end_date
        study_time = _sequence_time(sequence)
        metadata[study_uid] = {
            "date": fake_date.strftime("%Y%m%d"),
            "time": study_time,
            "accession": _accession_for(fake_date, sequence),
            "sequence": sequence,
        }

    with _STUDY_META_LOCK:
        _STUDY_META_BY_UID.clear()
        _STUDY_META_BY_UID.update(metadata)

    _info("Synthetic study metadata assigned", studies=total, end_date=end_date.isoformat())


def _fallback_study_metadata(study_uid: str) -> dict[str, str | int]:
    import hashlib as _hl
    sequence = int(_hl.md5(study_uid.encode()).hexdigest()[:6], 16) % 9000 + 1
    fake_date = _study_end_date() - datetime.timedelta(days=sequence % 90)
    return {
        "date": fake_date.strftime("%Y%m%d"),
        "time": _sequence_time(sequence),
        "accession": _accession_for(fake_date, sequence),
        "sequence": sequence,
    }


def _next_synthetic_study_metadata() -> dict[str, str | int]:
    global _SYNTHETIC_SEQUENCE
    with _STUDY_META_LOCK:
        if _SYNTHETIC_SEQUENCE == 0:
            _SYNTHETIC_SEQUENCE = int(_now_local().strftime("%H%M")) - 1
        _SYNTHETIC_SEQUENCE += 1
        sequence = _SYNTHETIC_SEQUENCE
    fake_date = _study_end_date()
    return {
        "date": fake_date.strftime("%Y%m%d"),
        "time": _sequence_time(sequence),
        "accession": _accession_for(fake_date, sequence),
        "sequence": sequence,
    }


def _apply_operational_metadata(
    ds: pydicom.Dataset,
    study_uid: str,
    meta: dict[str, str | int] | None = None,
) -> pydicom.Dataset:
    if meta is None:
        with _STUDY_META_LOCK:
            meta = _STUDY_META_BY_UID.get(study_uid)
    if meta is None:
        meta = _fallback_study_metadata(study_uid)

    date = str(meta["date"])
    time_value = str(meta["time"])

    ds.StudyDate = date
    ds.SeriesDate = date
    ds.AcquisitionDate = date
    ds.ContentDate = date
    ds.StudyTime = time_value
    ds.SeriesTime = time_value
    ds.AcquisitionTime = time_value
    ds.ContentTime = time_value
    ds.PerformedProcedureStepStartDate = date
    ds.PerformedProcedureStepStartTime = time_value
    ds.InstanceCreationDate = date
    ds.InstanceCreationTime = time_value
    if "AcquisitionDateTime" in ds:
        ds.AcquisitionDateTime = f"{date}{time_value}"
    ds.AccessionNumber = str(meta["accession"])
    ds.StudyID = f"S{int(meta['sequence']):04d}"
    return ds


# ── TCIA data discovery ───────────────────────────────────────

def _group_by_study(files: list[pathlib.Path]) -> dict[str, list[pathlib.Path]]:
    studies: dict[str, list[pathlib.Path]] = {}
    for f in files:
        try:
            ds  = pydicom.dcmread(str(f), stop_before_pixels=True)
            uid = str(getattr(ds, "StudyInstanceUID", "unknown"))
            studies.setdefault(uid, []).append(f)
        except Exception:
            pass
    return studies


def _modality_matches(path: pathlib.Path) -> bool:
    if MODALITY == "ANY":
        return True
    accepted = _ACCEPTED_DICOM_MODALITIES.get(MODALITY, {MODALITY})
    try:
        ds = pydicom.dcmread(str(path), stop_before_pixels=True)
        return getattr(ds, "Modality", "").upper() in accepted
    except Exception:
        return False


def wait_for_tcia_data() -> dict[str, list[pathlib.Path]]:
    deadline      = time.monotonic() + TCIA_WAIT_MINUTES * 60
    poll_interval = 10

    while time.monotonic() < deadline:
        if TCIA_SENTINEL.exists():
            break
        if list(TCIA_DATA_DIR.rglob("*.dcm")):
            _info("TCIA files found without sentinel", data_dir=str(TCIA_DATA_DIR))
            break
        _info("Waiting for TCIA loader",
              timeout_remaining_s=round(deadline - time.monotonic()))
        time.sleep(poll_interval)
    else:
        _warning("TCIA loader timed out — using synthetic data",
                 waited_minutes=TCIA_WAIT_MINUTES)
        return {}

    all_dcm = list(TCIA_DATA_DIR.rglob("*.dcm"))
    if not all_dcm:
        _warning("Sentinel found but no .dcm files — using synthetic data")
        return {}

    matched = [f for f in all_dcm if _modality_matches(f)]
    if matched:
        s = _group_by_study(matched)
        _build_study_metadata(s)
        _info("TCIA data loaded (modality-matched)",
              studies=len(s), files=len(matched), modality=MODALITY)
        return s

    _warning(
        "No modality-matched files — using synthetic same-modality data",
        requested=MODALITY,
        accepted_modalities=sorted(_ACCEPTED_DICOM_MODALITIES.get(MODALITY, {MODALITY})),
        total_files=len(all_dcm),
    )
    return {}


# ── Synthetic image generator ─────────────────────────────────
#
# Produces a proper, viewable DICOM image:
#   - 512×512 pixels with clinically plausible intensity range
#   - Correct file meta, transfer syntax, photometric interpretation
#   - Window center/width so viewers auto-open it correctly
#   - Per-modality pixel patterns (not pure noise)

def _make_ct_pixels(rows: int, cols: int) -> np.ndarray:
    """CT-like image: dark background, bright circular 'anatomy'."""
    img = np.full((rows, cols), -1000, dtype=np.int16)  # air HU
    cx, cy = cols // 2, rows // 2
    for y in range(rows):
        for x in range(cols):
            r = ((x - cx) ** 2 + (y - cy) ** 2) ** 0.5
            if r < 180:   # body
                img[y, x] = random.randint(-200, 80)
            if r < 140:   # soft tissue
                img[y, x] = random.randint(20, 80)
            if r < 60:    # "spine" / dense structure
                img[y, x] = random.randint(200, 800)
    return img

def _make_mri_pixels(rows: int, cols: int) -> np.ndarray:
    """MRI-like T1 brain: grey background with bright oval structures."""
    img = np.zeros((rows, cols), dtype=np.uint16)
    cx, cy = cols // 2, rows // 2
    for y in range(rows):
        for x in range(cols):
            r = ((x - cx) ** 2 + (y - cy) ** 2) ** 0.5
            if r < 200:
                img[y, x] = random.randint(200, 600)
            if r < 150:
                img[y, x] = random.randint(600, 2000)
            if r < 80:
                img[y, x] = random.randint(2000, 3500)
    return img

def _make_cr_pixels(rows: int, cols: int) -> np.ndarray:
    """Chest X-ray-like: bright periphery (ribs), dark centre (lungs)."""
    img = np.full((rows, cols), 3000, dtype=np.uint16)
    cx, cy = cols // 2, rows // 2
    for y in range(rows):
        for x in range(cols):
            r = ((x - cx) ** 2 + (y - cy) ** 2) ** 0.5
            if r < 220:   # lung fields
                img[y, x] = random.randint(200, 800)
            if r < 60:    # mediastinum
                img[y, x] = random.randint(2500, 3500)
    return img


def _make_nm_pixels(rows: int, cols: int) -> np.ndarray:
    """Nuclear medicine / bone scan: sparse hot spots on dark background."""
    img = np.zeros((rows, cols), dtype=np.uint16)
    cx, cy = cols // 2, rows // 2
    # Skeleton-like uptake pattern: spine, pelvis, joints
    hotspots = [
        (cy - 180, cx, 25), (cy - 140, cx, 20), (cy - 100, cx, 20),
        (cy - 60,  cx, 20), (cy - 20,  cx, 22), (cy + 20,  cx, 22),
        (cy + 60,  cx, 35), (cy + 100, cx, 30),  # pelvis
        (cy + 60,  cx - 80, 20), (cy + 60, cx + 80, 20),  # hip joints
        (cy - 160, cx - 40, 15), (cy - 160, cx + 40, 15),  # shoulders
    ]
    for hy, hx, hr in hotspots:
        for y in range(max(0, hy - hr), min(rows, hy + hr)):
            for x in range(max(0, hx - hr), min(cols, hx + hr)):
                r = ((x - hx)**2 + (y - hy)**2)**0.5
                if r < hr:
                    img[y, x] = int(random.randint(800, 3500) * (1 - r / hr))
    return img


def generate_synthetic_dataset(
    operational_meta: dict[str, str | int] | None = None,
    study_instance_uid: str | None = None,
) -> FileDataset:
    """
    Build a viewable DICOM file dataset with proper file meta,
    transfer syntax, pixel data, and window settings.
    """
    name, dob, sex, patient_id, physician = random.choice(_PATIENT_POOL)
    now_utc        = datetime.datetime.now(datetime.UTC)
    rows, cols     = 512, 512

    # ── File meta ──────────────────────────────────────────────
    sop_instance_uid = uid_mod.generate_uid()
    file_meta = FileMetaDataset()
    file_meta.MediaStorageSOPClassUID    = PRIMARY_SOP
    file_meta.MediaStorageSOPInstanceUID = sop_instance_uid
    file_meta.TransferSyntaxUID          = pydicom.uid.ExplicitVRLittleEndian
    file_meta.ImplementationClassUID     = uid_mod.generate_uid()
    file_meta.ImplementationVersionName  = "HIPAA-RANGE-SIM"

    # ── Dataset ────────────────────────────────────────────────
    ds = FileDataset(
        filename_or_obj=None,
        dataset={},
        file_meta=file_meta,
        is_implicit_VR=False,
        is_little_endian=True,
        preamble=b"\x00" * 128,
    )

    # Patient
    ds.PatientName          = name
    ds.PatientID            = patient_id
    ds.PatientBirthDate     = dob
    ds.PatientSex           = sex
    ds.PatientAge           = f"{(now_utc.year - int(dob[:4])):03d}Y"

    # Study
    synthetic_meta          = operational_meta or _next_synthetic_study_metadata()
    ds.StudyDate            = str(synthetic_meta["date"])
    ds.StudyTime            = str(synthetic_meta["time"])
    ds.AccessionNumber      = str(synthetic_meta["accession"])
    ds.StudyDescription     = STUDY_DESCRIPTIONS.get(MODALITY, "Imaging Study")
    ds.StudyInstanceUID     = study_instance_uid or uid_mod.generate_uid()
    ds.StudyID              = f"S{int(synthetic_meta['sequence']):04d}"
    ds.ReferringPhysicianName = physician

    # Series
    ds.Modality             = MODALITY
    ds.SeriesDescription    = f"{MODALITY} Series 1"
    ds.SeriesInstanceUID    = uid_mod.generate_uid()
    ds.SeriesNumber         = "1"
    ds.BodyPartExamined     = {"CT": "CHEST", "MR": "BRAIN", "MRI": "BRAIN", "CR": "CHEST", "DX": "CHEST", "XR": "CHEST"}.get(MODALITY, "CHEST")

    # Equipment
    ds.InstitutionName      = HOSPITAL_NAME
    if HOSPITAL_ADDRESS:
        ds.InstitutionAddress = HOSPITAL_ADDRESS
    ds.StationName          = AET
    ds.Manufacturer         = "HIPAA Range Simulator"
    ds.ManufacturerModelName= f"{MODALITY}-SIM-v1"

    # Instance
    ds.SOPClassUID          = PRIMARY_SOP
    ds.SOPInstanceUID       = sop_instance_uid
    ds.InstanceNumber       = "1"
    ds.ImageType            = ["ORIGINAL", "PRIMARY"]
    ds.AcquisitionDate      = ds.StudyDate
    ds.AcquisitionTime      = ds.StudyTime
    ds.ContentDate          = ds.StudyDate
    ds.ContentTime          = ds.StudyTime
    ds.SeriesDate           = ds.StudyDate
    ds.SeriesTime           = ds.StudyTime
    ds.PerformedProcedureStepStartDate = ds.StudyDate
    ds.PerformedProcedureStepStartTime = ds.StudyTime
    ds.InstanceCreationDate = ds.StudyDate
    ds.InstanceCreationTime = ds.StudyTime

    # Image geometry
    ds.Rows                 = rows
    ds.Columns              = cols
    ds.PixelSpacing         = [0.7, 0.7]
    ds.SliceThickness       = "5.0"
    ds.ImageOrientationPatient = [1, 0, 0, 0, 1, 0]
    ds.ImagePositionPatient    = [0.0, 0.0, 0.0]

    # Pixel data settings
    ds.SamplesPerPixel      = 1
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.BitsAllocated        = 16
    ds.BitsStored           = 16
    ds.HighBit              = 15
    ds.PixelRepresentation  = 0   # unsigned

    # Generate modality-appropriate pixel pattern
    if MODALITY == "CT":
        pixels = _make_ct_pixels(rows, cols)
        ds.RescaleIntercept     = "-1024"
        ds.RescaleSlope         = "1"
        ds.RescaleType          = "HU"
        ds.WindowCenter         = "40"
        ds.WindowWidth          = "400"
        ds.PixelRepresentation  = 1   # signed for CT HU values
        ds.BitsStored           = 16
        ds.HighBit              = 15
        pixel_bytes             = pixels.astype(np.int16).tobytes()
    elif MODALITY == "MR":
        pixels = _make_mri_pixels(rows, cols)
        ds.WindowCenter         = "1800"
        ds.WindowWidth          = "3500"
        pixel_bytes             = pixels.astype(np.uint16).tobytes()
    elif MODALITY == "NM":
        pixels = _make_nm_pixels(rows, cols)
        ds.WindowCenter         = "1500"
        ds.WindowWidth          = "3000"
        pixel_bytes             = pixels.astype(np.uint16).tobytes()
    else:  # CR / XR
        pixels = _make_cr_pixels(rows, cols)
        ds.WindowCenter         = "2048"
        ds.WindowWidth          = "4096"
        pixel_bytes             = pixels.astype(np.uint16).tobytes()

    ds.PixelData = pixel_bytes

    # Ensure transfer syntax is set on the dataset itself
    ds.file_meta.TransferSyntaxUID = pydicom.uid.ExplicitVRLittleEndian
    ds.is_implicit_VR   = False
    ds.is_little_endian = True

    return ds


# ── DICOM SCP (echo server — separate AE instance) ────────────

def _handle_echo(event) -> int:
    return 0x0000  # Success


def start_echo_server() -> None:
    """
    Spin up a dedicated SCP AE for C-ECHO on DICOM_LISTEN_PORT.
    Uses a SEPARATE AE instance from the outbound SCU so pynetdicom
    doesn't serialise inbound and outbound connections on the same object.
    The 'TCP Init Error: Operation now in progress' error is caused by
    calling ae.associate() while ae.start_server() holds the same AE's
    server socket — fixed by using two independent AE objects.
    """
    scp_ae = AE(ae_title=AET)
    scp_ae.add_supported_context(Verification)          # C-ECHO
    for ctx in StoragePresentationContexts:             # accept C-STORE too
        scp_ae.add_supported_context(ctx.abstract_syntax)

    handlers = [(evt.EVT_C_ECHO, _handle_echo)]

    def _serve():
        try:
            scp_ae.start_server(
                ("0.0.0.0", DICOM_LISTEN_PORT),
                block=True,
                evt_handlers=handlers,
            )
        except Exception as exc:
            _warning("Echo server stopped unexpectedly", error=str(exc))

    t = threading.Thread(target=_serve, daemon=True, name="dicom-scp")
    t.start()
    _info("DICOM SCP started", listen_port=DICOM_LISTEN_PORT, aet=AET)


# ── SCU (outbound C-STORE) ────────────────────────────────────

# Common uncompressed and compressed transfer syntaxes used by TCIA.
# CR/DX X-ray collections often use JPEG Lossless; request it explicitly
# so the simulator can forward real image pixels without transcoding.
_TRANSFER_SYNTAXES = [
    pydicom.uid.ExplicitVRLittleEndian,   # modern default
    pydicom.uid.ImplicitVRLittleEndian,   # legacy / TCIA files
    pydicom.uid.ExplicitVRBigEndian,      # rare but present in old datasets
    "1.2.840.10008.1.2.1.99",             # Deflated Explicit VR Little Endian
    "1.2.840.10008.1.2.4.50",             # JPEG Baseline (Process 1)
    "1.2.840.10008.1.2.4.51",             # JPEG Extended (Process 2 & 4)
    "1.2.840.10008.1.2.4.57",             # JPEG Lossless, Non-Hierarchical
    "1.2.840.10008.1.2.4.70",             # JPEG Lossless, First-Order Prediction
    "1.2.840.10008.1.2.4.80",             # JPEG-LS Lossless
    "1.2.840.10008.1.2.4.81",             # JPEG-LS Near-Lossless
    "1.2.840.10008.1.2.4.90",             # JPEG 2000 Lossless
    "1.2.840.10008.1.2.4.91",             # JPEG 2000
    "1.2.840.10008.1.2.5",                # RLE Lossless
]


def build_scu_ae() -> AE:
    """
    Build a dedicated SCU AE for outbound C-STORE.
    Each SOP class is requested with all three standard transfer syntaxes
    so the association succeeds regardless of what transfer syntax the
    source DICOM file was encoded with.
    """
    scu = AE(ae_title=AET)
    # Add PRIMARY_SOP explicitly first with all transfer syntaxes
    scu.add_requested_context(PRIMARY_SOP, _TRANSFER_SYNTAXES)
    # Add the full storage context list (covers CT, MRI, CR, PET, etc.)
    # pynetdicom deduplicates — safe to add PRIMARY_SOP again
    for ctx in StoragePresentationContexts:
        scu.add_requested_context(ctx.abstract_syntax, _TRANSFER_SYNTAXES)
    return scu


def _prepare_for_cstore(ds: pydicom.Dataset, source_path: str = "") -> pydicom.Dataset:
    transfer_syntax = getattr(getattr(ds, "file_meta", None), "TransferSyntaxUID", None)
    if not transfer_syntax or not getattr(transfer_syntax, "is_compressed", False):
        return ds

    try:
        try:
            ds.decompress(generate_instance_uid=False)
        except TypeError:
            ds.decompress()

        ds.file_meta.TransferSyntaxUID = pydicom.uid.ExplicitVRLittleEndian
        ds.is_implicit_VR = False
        ds.is_little_endian = True
        _info(
            "Decompressed DICOM for C-STORE",
            source_path=source_path,
            original_transfer_syntax=str(transfer_syntax),
        )
        return ds
    except Exception as exc:
        _warning(
            "Could not decompress DICOM before C-STORE",
            source_path=source_path,
            transfer_syntax=str(transfer_syntax),
            error=str(exc),
        )
        raise


def _remap_operational_uids(
    ds: pydicom.Dataset,
    transmitted_study_uid: str,
    series_uid_map: dict[str, str],
) -> pydicom.Dataset:
    original_series_uid = str(getattr(ds, "SeriesInstanceUID", uid_mod.generate_uid()))
    transmitted_series_uid = series_uid_map.setdefault(original_series_uid, uid_mod.generate_uid())
    transmitted_sop_uid = uid_mod.generate_uid()

    ds.StudyInstanceUID = transmitted_study_uid
    ds.SeriesInstanceUID = transmitted_series_uid
    ds.SOPInstanceUID = transmitted_sop_uid
    if getattr(ds, "file_meta", None) is not None:
        ds.file_meta.MediaStorageSOPInstanceUID = transmitted_sop_uid
        sop_class_uid = getattr(ds, "SOPClassUID", None) or getattr(ds.file_meta, "MediaStorageSOPClassUID", None)
        if sop_class_uid:
            ds.file_meta.MediaStorageSOPClassUID = sop_class_uid
    return ds


def send_study(
    scu: AE,
    study_files: list[pathlib.Path] | None,
    study_uid: str = "synthetic",
) -> dict:
    result: dict = {
        "study_uid":   study_uid,
        "files_sent":  0,
        "files_failed": 0,
        "status":      "unknown",
        "target":      f"{TARGET_HOST}:{TARGET_PORT}",
        "modality":    MODALITY,
        "requested_modality": REQUESTED_MODALITY,
        "device_modality_label": DEVICE_MODALITY_LABEL,
        "aet":         AET,
        "data_source": "tcia" if study_files else "synthetic",
    }

    try:
        assoc = scu.associate(TARGET_HOST, TARGET_PORT, ae_title=TARGET_AET)
        if not assoc.is_established:
            result["status"] = "association_failed"
            _error("DICOM association failed", **result)
            return result

        operational_meta = _next_synthetic_study_metadata()
        transmitted_study_uid = uid_mod.generate_uid()
        series_uid_map: dict[str, str] = {}

        files_to_send: list[pathlib.Path | None] = (
            study_files if study_files
            else [None] * 3   # 3 synthetic slices per burst
        )

        for item in files_to_send:
            try:
                if item:
                    # force=True handles missing or malformed preambles (common in TCIA)
                    ds = pydicom.dcmread(str(item), force=True)
                    # Re-stamp PHI: TCIA strips all patient identifiers.
                    # _stamp_phi assigns a deterministic fictional patient
                    # so Orthanc displays names, DOB, MRN, physician, etc.
                    ds = _stamp_phi(ds, study_uid, operational_meta)
                    # Preserve the original Modality tag from the TCIA file.
                    # Do NOT override it — CT files must stay CT, MR must stay MR.
                    # The simulator's MODALITY var controls which files are loaded,
                    # not what gets stamped on the wire.
                    ds = _remap_operational_uids(ds, transmitted_study_uid, series_uid_map)
                    ds = _prepare_for_cstore(ds, str(item))
                else:
                    ds = generate_synthetic_dataset(operational_meta, transmitted_study_uid)

                status = assoc.send_c_store(ds)
                if status and status.Status == 0x0000:
                    result["files_sent"] += 1
                else:
                    code = getattr(status, "Status", "?")
                    _warning("C-STORE non-success", status_code=hex(code), path=str(item))
                    result["files_failed"] += 1

            except Exception as exc:
                result["files_failed"] += 1
                _warning("C-STORE instance failed", path=str(item), error=str(exc))

        assoc.release()
        result["status"] = "success" if result["files_failed"] == 0 else "partial"

    except Exception as exc:
        result["status"] = "error"
        result["error"]  = str(exc)
        _error("C-STORE session error", **result)

    return result


# ── Main loop ─────────────────────────────────────────────────

def main() -> None:
    _info(
        "Modality simulator starting",
        modality=MODALITY,
        requested_modality=REQUESTED_MODALITY,
        device_modality_label=DEVICE_MODALITY_LABEL,
        aet=AET,
        target=f"{TARGET_HOST}:{TARGET_PORT}",
        target_aet=TARGET_AET,
        send_interval=SEND_INTERVAL,
        jitter_min=JITTER_MIN,
        jitter_max=JITTER_MAX,
        work_start=_raw_start,
        work_end=_raw_end,
        always_on=ALWAYS_ON,
        timezone=str(TZ),
        data_dir=str(TCIA_DATA_DIR),
        tcia_wait_minutes=TCIA_WAIT_MINUTES,
        listen_port=DICOM_LISTEN_PORT,
    )

    # Start SCP on its own AE — must happen before wait_for_tcia_data
    # so Orthanc can echo us green even during the loader wait
    start_echo_server()

    # Build a separate SCU AE for outbound sends
    scu = build_scu_ae()

    # Load TCIA data (or fall through to synthetic)
    studies    = wait_for_tcia_data()
    study_keys = list(studies.keys())

    if not studies:
        _warning(
            "No TCIA data — all transmissions will use synthetic viewable images",
            modality=MODALITY,
            device_modality_label=DEVICE_MODALITY_LABEL,
        )

    send_count = 0

    while True:

        # ── Working-hours gate ─────────────────────────────────
        if not is_within_working_hours():
            wait_secs = seconds_until_work_start()
            wake_at   = _now_local() + datetime.timedelta(seconds=wait_secs)
            _info(
                "Outside working hours — sleeping",
                current_time=_now_local().strftime("%H:%M"),
                work_start=_raw_start,
                work_end=_raw_end,
                timezone=str(TZ),
                sleeping_seconds=round(wait_secs),
                wake_at=wake_at.strftime("%Y-%m-%dT%H:%M:%S%z"),
            )
            _interruptible_sleep(wait_secs)
            continue

        # ── Send burst ─────────────────────────────────────────
        burst_start = time.monotonic()
        interval    = jittered_interval()

        for _ in range(STUDIES_PER_BURST):
            if study_keys:
                key    = random.choice(study_keys)
                result = send_study(scu, studies[key], study_uid=key)
            else:
                result = send_study(scu, None)

            send_count              += 1
            result["studies_sent"]   = send_count
            result["next_interval_s"] = round(interval, 1)
            _info("Study transmitted", **result)

        elapsed   = time.monotonic() - burst_start
        sleep_for = max(1.0, interval - elapsed)
        _debug(
            "Sleeping until next burst",
            sleep_seconds=round(sleep_for, 1),
            base_interval=SEND_INTERVAL,
            jitter_applied=round(interval - SEND_INTERVAL, 1),
        )
        _interruptible_sleep(sleep_for)


def _interruptible_sleep(total_seconds: float, chunk: float = 5.0) -> None:
    remaining = total_seconds
    while remaining > 0:
        time.sleep(min(chunk, remaining))
        remaining -= chunk


if __name__ == "__main__":
    main()
