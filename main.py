import calendar
import html
import json
import os
import uuid
import xml.etree.ElementTree as ET
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, Optional

import pymysql
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.exc import UnknownHashError
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field, model_validator
from pymysql.err import IntegrityError


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


load_dotenv(dotenv_path=Path(__file__).with_name(".env"), override=True)

DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_NAME = os.getenv("DB_NAME", "phplusv2_db")
DB_USER = os.getenv("DB_USER", "root")
DB_PASS = os.getenv("DB_PASS", "")

JWT_SECRET = os.getenv("JWT_SECRET", "replace-with-strong-secret")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_MINUTES = int(os.getenv("ACCESS_TOKEN_MINUTES", "1440"))
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@phplus.com").strip().lower()
ADMIN_PASSWORD_RAW = os.getenv("ADMIN_PASSWORD")
ADMIN_PASSWORD = ADMIN_PASSWORD_RAW.strip() if ADMIN_PASSWORD_RAW else None
FRONTEND_BASE_URL = os.getenv("FRONTEND_BASE_URL", "http://127.0.0.1:5757").strip().rstrip("/")

APP_HOST = os.getenv("APP_HOST", "127.0.0.1")
APP_PORT = int(os.getenv("APP_PORT", "8000"))
APP_RELOAD = env_bool("APP_RELOAD", default=False)
RESET_SCHEMA_ON_START = env_bool("RESET_SCHEMA_ON_START", default=False)
SEED_SAMPLE_DATA = env_bool("SEED_SAMPLE_DATA", default=False)

EntityType = Literal["event", "program", "activity"]
AssessmentType = Literal["phq9", "gad7", "dass21"]

ENTITY_TABLES: dict[EntityType, str] = {
    "event": "events",
    "program": "programs",
    "activity": "activities",
}

ENGAGE_ITEM_OFFSETS: dict[EntityType, int] = {
    "event": 0,
    "program": 1_000_000,
    "activity": 2_000_000,
}

ATTENDANCE_STATUSES = {"present", "late", "excused"}

HEALTH_SCREENING_ROOT = Path(__file__).resolve().parent / "health_screening"
HEALTH_SCREENING_FOLDER_FORMAT = "%d-%m-%Y"
FRONTEND_DIST_DIR = Path(__file__).resolve().parent / "dist"
FRONTEND_INDEX_FILE = FRONTEND_DIST_DIR / "index.html"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")
optional_oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=6, max_length=128)
    name: Optional[str] = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=6, max_length=128)


class AdminLoginRequest(BaseModel):
    password: str = Field(min_length=1, max_length=128)


class UpdateProfileRequest(BaseModel):
    name: Optional[str] = Field(default=None, max_length=150)
    identification_no: Optional[str] = Field(default=None, max_length=80)
    designation: Optional[str] = Field(default=None, max_length=120)
    department: Optional[str] = Field(default=None, max_length=120)
    dob: Optional[date] = None
    email: Optional[EmailStr] = None
    race: Optional[str] = Field(default=None, max_length=80)
    marital_status: Optional[str] = Field(default=None, max_length=50)
    gender: Optional[str] = Field(default=None, max_length=30)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=6, max_length=128)


class AdminResetPasswordRequest(BaseModel):
    new_password: str = Field(min_length=6, max_length=128)


class ModuleCreateRequest(BaseModel):
    title: str = Field(min_length=2, max_length=255)
    description: str = Field(min_length=2, max_length=5000)
    location: str = Field(min_length=2, max_length=255)
    starts_at: datetime
    ends_at: Optional[datetime] = None
    max_participants: int = Field(default=100, ge=1, le=100000)
    status: Literal["active", "inactive"] = "active"

    @model_validator(mode="after")
    def validate_dates(self):
        if self.ends_at and self.ends_at < self.starts_at:
            raise ValueError("ends_at must be later than starts_at")
        return self


class QRCodeCreateRequest(BaseModel):
    entity_type: EntityType
    entity_id: int = Field(ge=1)
    expires_in_hours: Optional[int] = Field(default=24, ge=1, le=24 * 30)


class AttendanceScanRequest(BaseModel):
    qr_token: str = Field(min_length=8, max_length=120)
    attendee_user_id: int = Field(ge=1)
    status: Literal["present", "late", "excused"] = "present"
    notes: Optional[str] = Field(default=None, max_length=255)


class HealthRecordCreateRequest(BaseModel):
    user_id: Optional[int] = Field(default=None, ge=1)
    weight_kg: Optional[float] = Field(default=None, ge=0, le=1000)
    height_cm: Optional[float] = Field(default=None, ge=0, le=300)
    systolic_bp: Optional[int] = Field(default=None, ge=40, le=300)
    diastolic_bp: Optional[int] = Field(default=None, ge=30, le=250)
    notes: Optional[str] = Field(default=None, max_length=255)

    @model_validator(mode="after")
    def validate_metrics(self):
        has_weight = self.weight_kg is not None
        has_height = self.height_cm is not None
        has_bp = self.systolic_bp is not None or self.diastolic_bp is not None

        if not has_weight and not has_height and not has_bp:
            raise ValueError("At least one metric is required")

        if (self.systolic_bp is None) != (self.diastolic_bp is None):
            raise ValueError("systolic_bp and diastolic_bp must be provided together")

        return self


class MentalAssessmentSubmitRequest(BaseModel):
    assessment_type: AssessmentType
    score: int = Field(ge=0)
    severity: str = Field(min_length=1, max_length=60)
    user_id: Optional[int] = Field(default=None, ge=1)
    notes: Optional[str] = Field(default=None, max_length=255)


def db_connect(db_name: Optional[str] = None):
    return pymysql.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASS,
        database=db_name,
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=False,
    )


def ensure_database() -> None:
    conn = db_connect(None)
    try:
        with conn.cursor() as cur:
            cur.execute(
                f"CREATE DATABASE IF NOT EXISTS `{DB_NAME}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
            )
        conn.commit()
    finally:
        conn.close()


def drop_all_tables() -> None:
    conn = db_connect(DB_NAME)
    try:
        with conn.cursor() as cur:
            cur.execute("SET FOREIGN_KEY_CHECKS=0")
            cur.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema=%s",
                (DB_NAME,),
            )
            table_names = [next(iter(row.values())) for row in cur.fetchall()]
            for table_name in table_names:
                cur.execute(f"DROP TABLE IF EXISTS `{table_name}`")
            cur.execute("SET FOREIGN_KEY_CHECKS=1")
        conn.commit()
    finally:
        conn.close()


def create_tables() -> None:
    ddl = [
        """
        CREATE TABLE IF NOT EXISTS users (
            id INT PRIMARY KEY AUTO_INCREMENT,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            name VARCHAR(150) NOT NULL,
            identification_no VARCHAR(80) NULL,
            designation VARCHAR(120) NULL,
            department VARCHAR(120) NULL,
            dob DATE NULL,
            race VARCHAR(80) NULL,
            marital_status VARCHAR(50) NULL,
            gender VARCHAR(30) NULL,
            role ENUM('staff','admin') NOT NULL DEFAULT 'staff',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """,
        """
        CREATE TABLE IF NOT EXISTS events (
            id INT PRIMARY KEY AUTO_INCREMENT,
            title VARCHAR(255) NOT NULL,
            description TEXT NOT NULL,
            location VARCHAR(255) NOT NULL,
            starts_at DATETIME NOT NULL,
            ends_at DATETIME NULL,
            max_participants INT NOT NULL DEFAULT 100,
            status ENUM('active','inactive') NOT NULL DEFAULT 'active',
            created_by INT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            CONSTRAINT fk_events_created_by FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """,
        """
        CREATE TABLE IF NOT EXISTS programs (
            id INT PRIMARY KEY AUTO_INCREMENT,
            title VARCHAR(255) NOT NULL,
            description TEXT NOT NULL,
            location VARCHAR(255) NOT NULL,
            starts_at DATETIME NOT NULL,
            ends_at DATETIME NULL,
            max_participants INT NOT NULL DEFAULT 100,
            status ENUM('active','inactive') NOT NULL DEFAULT 'active',
            created_by INT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            CONSTRAINT fk_programs_created_by FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """,
        """
        CREATE TABLE IF NOT EXISTS activities (
            id INT PRIMARY KEY AUTO_INCREMENT,
            title VARCHAR(255) NOT NULL,
            description TEXT NOT NULL,
            location VARCHAR(255) NOT NULL,
            starts_at DATETIME NOT NULL,
            ends_at DATETIME NULL,
            max_participants INT NOT NULL DEFAULT 100,
            status ENUM('active','inactive') NOT NULL DEFAULT 'active',
            created_by INT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            CONSTRAINT fk_activities_created_by FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """,
        """
        CREATE TABLE IF NOT EXISTS qr_codes (
            id INT PRIMARY KEY AUTO_INCREMENT,
            entity_type ENUM('event','program','activity') NOT NULL,
            entity_id INT NOT NULL,
            qr_token VARCHAR(120) UNIQUE NOT NULL,
            qr_payload VARCHAR(255) NOT NULL,
            is_active BOOLEAN NOT NULL DEFAULT TRUE,
            expires_at DATETIME NULL,
            created_by INT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_qr_entity (entity_type, entity_id),
            CONSTRAINT fk_qr_created_by FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """,
        """
        CREATE TABLE IF NOT EXISTS attendance_logs (
            id INT PRIMARY KEY AUTO_INCREMENT,
            entity_type ENUM('event','program','activity') NOT NULL,
            entity_id INT NOT NULL,
            qr_code_id INT NOT NULL,
            attendee_user_id INT NOT NULL,
            scanned_by_user_id INT NULL,
            status ENUM('present','late','excused') NOT NULL DEFAULT 'present',
            notes VARCHAR(255) NULL,
            scanned_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uq_attendance_once (entity_type, entity_id, attendee_user_id),
            INDEX idx_attendance_scanned_at (scanned_at),
            INDEX idx_attendance_attendee (attendee_user_id),
            CONSTRAINT fk_attendance_qr FOREIGN KEY (qr_code_id) REFERENCES qr_codes(id) ON DELETE CASCADE,
            CONSTRAINT fk_attendance_user FOREIGN KEY (attendee_user_id) REFERENCES users(id) ON DELETE CASCADE,
            CONSTRAINT fk_attendance_staff FOREIGN KEY (scanned_by_user_id) REFERENCES users(id) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """,
        """
        CREATE TABLE IF NOT EXISTS health_records (
            id INT PRIMARY KEY AUTO_INCREMENT,
            user_id INT NOT NULL,
            recorded_by INT NULL,
            weight_kg DECIMAL(5,2) NULL,
            height_cm DECIMAL(5,2) NULL,
            systolic_bp SMALLINT NULL,
            diastolic_bp SMALLINT NULL,
            notes VARCHAR(255) NULL,
            recorded_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_health_user_time (user_id, recorded_at),
            CONSTRAINT fk_health_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            CONSTRAINT fk_health_recorded_by FOREIGN KEY (recorded_by) REFERENCES users(id) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """,
        """
        CREATE TABLE IF NOT EXISTS mental_health_scores (
            id INT PRIMARY KEY AUTO_INCREMENT,
            user_id INT NOT NULL,
            assessment_type ENUM('phq9','gad7','dass21') NOT NULL,
            score SMALLINT NOT NULL,
            severity VARCHAR(60) NOT NULL,
            answers_json TEXT NOT NULL,
            notes VARCHAR(255) NULL,
            recorded_by INT NULL,
            recorded_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_mental_user_type_time (user_id, assessment_type, recorded_at),
            CONSTRAINT fk_mental_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            CONSTRAINT fk_mental_recorded_by FOREIGN KEY (recorded_by) REFERENCES users(id) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """,
    ]

    conn = db_connect(DB_NAME)
    try:
        with conn.cursor() as cur:
            for statement in ddl:
                cur.execute(statement)
            cur.execute(
                """
                SELECT COLUMN_NAME
                FROM information_schema.columns
                WHERE table_schema=%s AND table_name='users' AND column_name='full_name'
                """,
                (DB_NAME,),
            )
            has_full_name = cur.fetchone() is not None
            if has_full_name:
                cur.execute(
                    """
                    SELECT COLUMN_NAME
                    FROM information_schema.columns
                    WHERE table_schema=%s AND table_name='users' AND column_name='name'
                    """,
                    (DB_NAME,),
                )
                has_name = cur.fetchone() is not None
                if not has_name:
                    cur.execute("ALTER TABLE users CHANGE COLUMN full_name name VARCHAR(150) NOT NULL")
            cur.execute(
                """
                SELECT COLUMN_TYPE
                FROM information_schema.columns
                WHERE table_schema=%s AND table_name='users' AND column_name='role'
                """,
                (DB_NAME,),
            )
            role_column = cur.fetchone()
            role_column_type = (role_column or {}).get("COLUMN_TYPE", "")
            if "admin" not in str(role_column_type):
                cur.execute("ALTER TABLE users MODIFY COLUMN role ENUM('staff','admin') NOT NULL DEFAULT 'staff'")
            user_profile_columns = {
                "identification_no": "VARCHAR(80) NULL",
                "designation": "VARCHAR(120) NULL",
                "department": "VARCHAR(120) NULL",
                "dob": "DATE NULL",
                "race": "VARCHAR(80) NULL",
                "marital_status": "VARCHAR(50) NULL",
                "gender": "VARCHAR(30) NULL",
            }
            for column_name, column_ddl in user_profile_columns.items():
                cur.execute(
                    """
                    SELECT COLUMN_NAME
                    FROM information_schema.columns
                    WHERE table_schema=%s AND table_name='users' AND column_name=%s
                    """,
                    (DB_NAME, column_name),
                )
                if cur.fetchone() is None:
                    cur.execute(f"ALTER TABLE users ADD COLUMN `{column_name}` {column_ddl}")
        conn.commit()
    finally:
        conn.close()


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    # Legacy or manually-imported rows can contain invalid/empty hashes.
    # Treat them as invalid credentials instead of raising 500.
    try:
        return pwd_context.verify(plain, hashed)
    except (UnknownHashError, ValueError, TypeError):
        return False


def create_access_token(user_id: int) -> str:
    expires = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_MINUTES)
    payload = {"sub": str(user_id), "exp": expires}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def _normalized_optional_text(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned if cleaned else None


def _digits_only(value: Optional[str]) -> str:
    if not value:
        return ""
    return "".join(ch for ch in value if ch.isdigit())


def _current_user_ic_suffix(current_user: dict[str, Any]) -> Optional[str]:
    identification_no_digits = _digits_only(current_user.get("identification_no"))
    if len(identification_no_digits) < 4:
        return None
    return identification_no_digits[-4:]


ASSESSMENT_SEQUENCE: tuple[AssessmentType, ...] = ("phq9", "gad7", "dass21")
ASSESSMENT_LABELS: dict[AssessmentType, str] = {
    "phq9": "PHQ-9",
    "gad7": "GAD-7",
    "dass21": "DASS-21",
}
ASSESSMENT_SCORE_LIMITS: dict[AssessmentType, int] = {
    "phq9": 27,
    "gad7": 21,
    "dass21": 126,
}


def _load_latest_mental_assessments(cur: pymysql.cursors.DictCursor, user_id: int) -> dict[AssessmentType, dict[str, Any]]:
    snapshots: dict[AssessmentType, dict[str, Any]] = {
        assessment_type: {
            "assessment_type": assessment_type,
            "label": ASSESSMENT_LABELS[assessment_type],
            "score": None,
            "severity": "No Data",
            "recorded_at": None,
        }
        for assessment_type in ASSESSMENT_SEQUENCE
    }

    cur.execute(
        """
        SELECT assessment_type, score, severity, recorded_at
        FROM mental_health_scores
        WHERE user_id=%s
        ORDER BY recorded_at DESC, id DESC
        """,
        (user_id,),
    )
    rows = cur.fetchall()
    for row in rows:
        assessment_type = row["assessment_type"]
        if assessment_type not in snapshots:
            continue
        if snapshots[assessment_type]["recorded_at"] is not None:
            continue
        snapshots[assessment_type] = {
            "assessment_type": assessment_type,
            "label": ASSESSMENT_LABELS[assessment_type],
            "score": int(row["score"]),
            "severity": row["severity"],
            "recorded_at": row["recorded_at"].isoformat() if row.get("recorded_at") else None,
        }

    return snapshots


def _clean_xml_text(value: Optional[str]) -> str:
    if value is None:
        return ""
    return html.unescape(value).strip()


def _xml_child_text(node: Optional[ET.Element], child_tag: str) -> str:
    if node is None:
        return ""
    return _clean_xml_text(node.findtext(child_tag))


def _humanize_xml_tag(raw_tag: str) -> str:
    return raw_tag.replace("_", " ").strip()


def _parse_health_screening_folder_date(folder_name: str) -> Optional[date]:
    try:
        return datetime.strptime(folder_name, HEALTH_SCREENING_FOLDER_FORMAT).date()
    except ValueError:
        return None


def _health_screening_folder_payload(folder_name: str) -> dict[str, Any]:
    folder_date = _parse_health_screening_folder_date(folder_name)
    return {
        "folder": folder_name,
        "date": folder_date.isoformat() if folder_date else None,
        "label": folder_date.strftime("%d %b %Y") if folder_date else folder_name,
    }


def _list_health_screening_folders() -> list[Path]:
    if not HEALTH_SCREENING_ROOT.exists() or not HEALTH_SCREENING_ROOT.is_dir():
        return []

    folders = [path for path in HEALTH_SCREENING_ROOT.iterdir() if path.is_dir()]
    folders.sort(
        key=lambda path: (_parse_health_screening_folder_date(path.name) or date.min, path.name.lower()),
        reverse=True,
    )
    return folders


def _resolve_health_screening_folder(folder_name: str) -> Path:
    root_path = HEALTH_SCREENING_ROOT.resolve()
    candidate = (HEALTH_SCREENING_ROOT / folder_name).resolve()

    try:
        candidate.relative_to(root_path)
    except ValueError:
        raise HTTPException(status_code=404, detail="Health screening folder not found")

    if not candidate.exists() or not candidate.is_dir():
        raise HTTPException(status_code=404, detail="Health screening folder not found")

    return candidate


def _iter_xml_files(folder_path: Path) -> list[Path]:
    return sorted((file_path for file_path in folder_path.iterdir() if file_path.suffix.lower() == ".xml"), reverse=True)


def _read_xml_root(xml_path: Path) -> Optional[ET.Element]:
    try:
        return ET.parse(xml_path).getroot()
    except (ET.ParseError, OSError):
        return None


def _xml_matches_user_ic(root: ET.Element, user_ic_suffix: str) -> bool:
    record_node = root.find("RECORD")
    xml_ic_digits = _digits_only(_xml_child_text(record_node, "IC"))
    if not xml_ic_digits:
        return False
    return xml_ic_digits.endswith(user_ic_suffix)


def _extract_lab_test_item(test_node: ET.Element) -> Optional[dict[str, Any]]:
    name = _xml_child_text(test_node, "name") or _humanize_xml_tag(test_node.tag)
    param1 = _xml_child_text(test_node, "param1")
    param2 = _xml_child_text(test_node, "param2")
    param3 = _xml_child_text(test_node, "param3")
    units = _xml_child_text(test_node, "units")
    status = _xml_child_text(test_node, "outside_normal").upper()
    lower_limit = _xml_child_text(test_node, "lower_limit")
    upper_limit = _xml_child_text(test_node, "upper_limit")

    value = param2 or param1 or param3
    notes = []
    if param1 and param1 != value:
        notes.append(param1)
    if param3 and param3 != value:
        notes.append(param3)

    has_content = any([name, value, units, status, lower_limit, upper_limit, param1, param2, param3, notes])
    if not has_content:
        return None

    return {
        "id": test_node.tag,
        "name": name,
        "value": value,
        "units": units,
        "status": status,
        "lower_limit": lower_limit,
        "upper_limit": upper_limit,
        "param1": param1,
        "param2": param2,
        "param3": param3,
        "notes": notes,
    }


def _extract_lab_sections(record_node: Optional[ET.Element]) -> list[dict[str, Any]]:
    if record_node is None:
        return []

    sections: list[dict[str, Any]] = []
    for section_node in list(record_node):
        test_nodes = list(section_node)
        if not test_nodes:
            continue

        tests: list[dict[str, Any]] = []
        for test_node in test_nodes:
            if not list(test_node):
                continue
            parsed_test = _extract_lab_test_item(test_node)
            if parsed_test:
                tests.append(parsed_test)

        if tests:
            sections.append(
                {
                    "id": section_node.tag,
                    "name": _humanize_xml_tag(section_node.tag),
                    "tests": tests,
                }
            )

    return sections


def _serialize_lab_result(root: ET.Element, source_file: str, folder_name: str) -> dict[str, Any]:
    header_node = root.find("HEADER")
    record_node = root.find("RECORD")
    sections = _extract_lab_sections(record_node)
    tests_count = sum(len(section["tests"]) for section in sections)

    return {
        "folder": _health_screening_folder_payload(folder_name),
        "source_file": source_file,
        "tests_count": tests_count,
        "header": {
            "lab_name": _xml_child_text(header_node, "LAB_NAME"),
            "event_name": _xml_child_text(header_node, "EVENT_NAME"),
            "date_file": _xml_child_text(header_node, "DATE_FILE"),
        },
        "record": {
            "ref_no": _xml_child_text(record_node, "REF_NO"),
            "pin_no": _xml_child_text(record_node, "PIN_NO"),
            "ic": _xml_child_text(record_node, "IC"),
            "lab_no": _xml_child_text(record_node, "LAB_NO"),
            "doctor_name": _xml_child_text(record_node, "DR_NAME"),
            "clinic_address": _xml_child_text(record_node, "CLINIC_ADDR"),
            "collection_date": _xml_child_text(record_node, "COLL_DATE"),
            "collection_time": _xml_child_text(record_node, "COLL_TIME"),
            "registered_date": _xml_child_text(record_node, "REGD_DATE"),
            "registered_time": _xml_child_text(record_node, "REGD_TIME"),
            "printed_date": _xml_child_text(record_node, "PRNT_DATE"),
            "printed_time": _xml_child_text(record_node, "PRNT_TIME"),
        },
        "sections": sections,
    }


def _count_user_results_in_folder(folder_path: Path, user_ic_suffix: str) -> int:
    total = 0
    for xml_path in _iter_xml_files(folder_path):
        root = _read_xml_root(xml_path)
        if root is None:
            continue
        if _xml_matches_user_ic(root, user_ic_suffix):
            total += 1
    return total


def _find_user_lab_result(folder_path: Path, user_ic_suffix: str) -> Optional[dict[str, Any]]:
    for xml_path in _iter_xml_files(folder_path):
        root = _read_xml_root(xml_path)
        if root is None:
            continue
        if not _xml_matches_user_ic(root, user_ic_suffix):
            continue
        return _serialize_lab_result(root, xml_path.name, folder_path.name)
    return None


def serialize_user_row(user: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": user["id"],
        "email": user["email"],
        "name": user["name"],
        "role": user["role"],
        "identification_no": user.get("identification_no"),
        "designation": user.get("designation"),
        "department": user.get("department"),
        "dob": user["dob"].isoformat() if user.get("dob") else None,
        "race": user.get("race"),
        "marital_status": user.get("marital_status"),
        "gender": user.get("gender"),
        "created_at": user["created_at"].isoformat() if user.get("created_at") else None,
    }


def serialize_module_row(row: dict[str, Any], entity_type: EntityType) -> dict[str, Any]:
    return {
        "id": row["id"],
        "type": entity_type,
        "title": row["title"],
        "description": row["description"],
        "location": row["location"],
        "starts_at": row["starts_at"].isoformat() if row["starts_at"] else None,
        "ends_at": row["ends_at"].isoformat() if row["ends_at"] else None,
        "max_participants": row["max_participants"],
        "status": row["status"],
        "created_by": row["created_by"],
        "created_at": row["created_at"].isoformat() if row["created_at"] else None,
    }


def seed_default_users() -> None:
    admin_name = "PHPlus Administrator"

    conn = db_connect(DB_NAME)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id
                FROM users
                WHERE role='admin'
                ORDER BY id ASC
                LIMIT 1
                """
            )
            existing_admin = cur.fetchone()
            if not existing_admin:
                cur.execute("SELECT id FROM users WHERE email=%s LIMIT 1", (ADMIN_EMAIL,))
                existing_admin_email = cur.fetchone()

                if existing_admin_email:
                    cur.execute(
                        """
                        UPDATE users
                        SET role='admin', name=%s
                        WHERE id=%s
                        """,
                        (admin_name, existing_admin_email["id"]),
                    )
                elif ADMIN_PASSWORD:
                    admin_password_hash = hash_password(ADMIN_PASSWORD)
                    cur.execute(
                        "INSERT INTO users(email,password_hash,name,role) VALUES(%s,%s,%s,'admin')",
                        (ADMIN_EMAIL, admin_password_hash, admin_name),
                    )
                else:
                    print(
                        "Warning: No admin user found and ADMIN_PASSWORD is not set; "
                        "admin account was not auto-created."
                    )
        conn.commit()
    finally:
        conn.close()


def seed_sample_modules() -> None:
    now = datetime.now()
    start_of_today = now.replace(hour=0, minute=0, second=0, microsecond=0)

    def at(day_offset: int, hour: int, minute: int = 0) -> datetime:
        return start_of_today + timedelta(days=day_offset, hours=hour, minutes=minute)

    conn = db_connect(DB_NAME)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users ORDER BY id ASC LIMIT 1")
            staff = cur.fetchone()
            created_by = staff["id"] if staff else None

            sample_rows = {
                "events": [
                    (
                        "Daily Wellness Briefing",
                        "Quick briefing on today's health and safety updates.",
                        "HQ Auditorium",
                        now - timedelta(minutes=45),
                        now + timedelta(minutes=75),
                        120,
                        "active",
                        created_by,
                    ),
                    (
                        "Nutrition Awareness Seminar",
                        "Seminar on practical food choices for better daily health.",
                        "Training Room A",
                        at(1, 9),
                        at(1, 11),
                        150,
                        "active",
                        created_by,
                    ),
                    (
                        "Heart Health Forum",
                        "Talk session with medical team on heart health and prevention steps.",
                        "Lecture Room B",
                        at(2, 14),
                        at(2, 16),
                        110,
                        "active",
                        created_by,
                    ),
                    (
                        "Workplace Ergonomics Talk",
                        "How to reduce neck and back pain while working.",
                        "Conference Hall",
                        at(3, 10),
                        at(3, 12),
                        90,
                        "active",
                        created_by,
                    ),
                    (
                        "Diabetes Prevention Workshop",
                        "Practical workshop on blood sugar monitoring and healthy lifestyle routines.",
                        "Education Hub 1",
                        at(4, 9),
                        at(4, 11),
                        80,
                        "active",
                        created_by,
                    ),
                    (
                        "Mental Wellness Sharing",
                        "Open sharing session on stress awareness and emotional wellbeing.",
                        "Community Hall",
                        at(5, 15),
                        at(5, 17),
                        100,
                        "active",
                        created_by,
                    ),
                ],
                "programs": [
                    (
                        "Weight Management Kickoff",
                        "Structured nutrition and activity plan with weekly check-ins and coaching.",
                        "PHPlus Wellness Center",
                        now + timedelta(hours=2),
                        now + timedelta(hours=4),
                        60,
                        "active",
                        created_by,
                    ),
                    (
                        "Cardio Fitness Program Cohort A",
                        "Progressive cardio sessions for improving endurance.",
                        "Gym Studio 2",
                        at(1, 8),
                        at(1, 10),
                        50,
                        "active",
                        created_by,
                    ),
                    (
                        "Stress Management Program Batch 2",
                        "Guided activities focused on stress control and recovery.",
                        "Mind Care Unit",
                        at(2, 9),
                        at(2, 11),
                        40,
                        "active",
                        created_by,
                    ),
                    (
                        "Quit Smoking Support Program",
                        "Weekly support sessions for participants committed to quitting smoking.",
                        "Wellness Clinic Room 4",
                        at(3, 10),
                        at(3, 12),
                        35,
                        "active",
                        created_by,
                    ),
                    (
                        "Healthy Sleep Reset Program",
                        "Guided lifestyle coaching to improve sleep quality and consistency.",
                        "Recovery Studio",
                        at(4, 7),
                        at(4, 9),
                        45,
                        "active",
                        created_by,
                    ),
                ],
                "activities": [
                    (
                        "Morning Mobility Session",
                        "Guided low-impact movement session to encourage daily activity.",
                        "Lake Garden",
                        at(0, 7, 30),
                        at(0, 8, 30),
                        80,
                        "active",
                        created_by,
                    ),
                    (
                        "Lunchtime Stretching",
                        "Short guided stretching session for office staff.",
                        "Open Space Atrium",
                        at(1, 12, 30),
                        at(1, 13, 15),
                        70,
                        "active",
                        created_by,
                    ),
                    (
                        "Evening Yoga Session",
                        "Light yoga class to improve flexibility and breathing.",
                        "Wellness Deck",
                        at(2, 18),
                        at(2, 19),
                        45,
                        "active",
                        created_by,
                    ),
                    (
                        "Office Steps Challenge Meetup",
                        "Small group walk to track daily step goals together.",
                        "Main Lobby",
                        at(3, 17, 30),
                        at(3, 18, 15),
                        60,
                        "active",
                        created_by,
                    ),
                    (
                        "Weekend Fun Run",
                        "Community run focused on light cardio and social connection.",
                        "City Park Gate 2",
                        at(5, 6, 30),
                        at(5, 8),
                        120,
                        "active",
                        created_by,
                    ),
                ],
            }

            for table_name, rows in sample_rows.items():
                cur.execute(f"SELECT title FROM `{table_name}`")
                existing_titles = {row["title"] for row in cur.fetchall()}
                rows_to_insert = [row for row in rows if row[0] not in existing_titles]
                if not rows_to_insert:
                    continue
                cur.executemany(
                    f"""
                    INSERT INTO `{table_name}`
                    (title,description,location,starts_at,ends_at,max_participants,status,created_by)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    rows_to_insert,
                )
        conn.commit()
    finally:
        conn.close()


def rebuild_schema(drop_existing: bool = False, seed_data: bool = True) -> None:
    # ensure_database()  # DB is pre-created by DBA; app user has no CREATE DATABASE privilege
    if drop_existing:
        drop_all_tables()
    create_tables()
    seed_default_users()
    if seed_data:
        seed_sample_modules()


def get_current_user(token: str = Depends(oauth2_scheme)) -> dict[str, Any]:
    unauthorized = HTTPException(status_code=401, detail="Invalid authentication token")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("sub")
        if not user_id:
            raise unauthorized
        parsed_user_id = int(user_id)
    except JWTError:
        raise unauthorized
    except (TypeError, ValueError):
        raise unauthorized

    conn = db_connect(DB_NAME)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    id,
                    email,
                    name,
                    role,
                    identification_no,
                    designation,
                    department,
                    dob,
                    race,
                    marital_status,
                    gender,
                    created_at
                FROM users
                WHERE id=%s
                """,
                (parsed_user_id,),
            )
            user = cur.fetchone()
            if not user:
                raise unauthorized
            return user
    finally:
        conn.close()


def get_optional_current_user(token: Optional[str] = Depends(optional_oauth2_scheme)) -> Optional[dict[str, Any]]:
    if not token:
        return None
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("sub")
        if not user_id:
            return None
        parsed_user_id = int(user_id)
    except JWTError:
        return None
    except (TypeError, ValueError):
        return None

    conn = db_connect(DB_NAME)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    id,
                    email,
                    name,
                    role,
                    identification_no,
                    designation,
                    department,
                    dob,
                    race,
                    marital_status,
                    gender,
                    created_at
                FROM users
                WHERE id=%s
                """,
                (parsed_user_id,),
            )
            user = cur.fetchone()
            return user
    finally:
        conn.close()


def require_staff_user(current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    return current_user


def require_admin_user(current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user


def fetch_modules(entity_type: EntityType) -> list[dict[str, Any]]:
    table_name = ENTITY_TABLES[entity_type]
    conn = db_connect(DB_NAME)
    try:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT id,title,description,location,starts_at,ends_at,max_participants,status,created_by,created_at
                FROM `{table_name}`
                ORDER BY starts_at DESC, id DESC
                """
            )
            rows = cur.fetchall()
            return [serialize_module_row(row, entity_type) for row in rows]
    finally:
        conn.close()


def _normalize_datetime_for_db(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    if value.tzinfo is None:
        return value
    return value.astimezone().replace(tzinfo=None)


def create_module(entity_type: EntityType, payload: ModuleCreateRequest, creator_id: int) -> dict[str, Any]:
    table_name = ENTITY_TABLES[entity_type]
    starts_at = _normalize_datetime_for_db(payload.starts_at)
    ends_at = _normalize_datetime_for_db(payload.ends_at)
    conn = db_connect(DB_NAME)
    try:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                INSERT INTO `{table_name}`
                (title,description,location,starts_at,ends_at,max_participants,status,created_by)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                (
                    payload.title,
                    payload.description,
                    payload.location,
                    starts_at,
                    ends_at,
                    payload.max_participants,
                    payload.status,
                    creator_id,
                ),
            )
            new_id = cur.lastrowid
            cur.execute(
                f"""
                SELECT id,title,description,location,starts_at,ends_at,max_participants,status,created_by,created_at
                FROM `{table_name}`
                WHERE id=%s
                """,
                (new_id,),
            )
            row = cur.fetchone()
        conn.commit()
        return serialize_module_row(row, entity_type)
    finally:
        conn.close()


def update_module(entity_type: EntityType, entity_id: int, payload: ModuleCreateRequest) -> dict[str, Any]:
    table_name = ENTITY_TABLES[entity_type]
    starts_at = _normalize_datetime_for_db(payload.starts_at)
    ends_at = _normalize_datetime_for_db(payload.ends_at)
    conn = db_connect(DB_NAME)
    try:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                UPDATE `{table_name}`
                SET
                    title=%s,
                    description=%s,
                    location=%s,
                    starts_at=%s,
                    ends_at=%s,
                    max_participants=%s,
                    status=%s
                WHERE id=%s
                """,
                (
                    payload.title,
                    payload.description,
                    payload.location,
                    starts_at,
                    ends_at,
                    payload.max_participants,
                    payload.status,
                    entity_id,
                ),
            )
            if cur.rowcount == 0:
                raise HTTPException(status_code=404, detail=f"{entity_type} not found")

            cur.execute(
                f"""
                SELECT id,title,description,location,starts_at,ends_at,max_participants,status,created_by,created_at
                FROM `{table_name}`
                WHERE id=%s
                """,
                (entity_id,),
            )
            row = cur.fetchone()
        conn.commit()
        return serialize_module_row(row, entity_type)
    finally:
        conn.close()


def delete_module(entity_type: EntityType, entity_id: int) -> dict[str, Any]:
    table_name = ENTITY_TABLES[entity_type]
    conn = db_connect(DB_NAME)
    try:
        with conn.cursor() as cur:
            cur.execute(f"SELECT id,title FROM `{table_name}` WHERE id=%s", (entity_id,))
            existing = cur.fetchone()
            if not existing:
                raise HTTPException(status_code=404, detail=f"{entity_type} not found")

            cur.execute(
                "DELETE FROM attendance_logs WHERE entity_type=%s AND entity_id=%s",
                (entity_type, entity_id),
            )
            cur.execute(
                "DELETE FROM qr_codes WHERE entity_type=%s AND entity_id=%s",
                (entity_type, entity_id),
            )
            cur.execute(f"DELETE FROM `{table_name}` WHERE id=%s", (entity_id,))
        conn.commit()
        return {"deleted": True, "entity_type": entity_type, "entity_id": entity_id}
    finally:
        conn.close()


def get_entity(conn, entity_type: EntityType, entity_id: int) -> Optional[dict[str, Any]]:
    table_name = ENTITY_TABLES[entity_type]
    with conn.cursor() as cur:
        cur.execute(
            f"SELECT id,title,status,starts_at,ends_at,max_participants FROM `{table_name}` WHERE id=%s",
            (entity_id,),
        )
        return cur.fetchone()


def _encode_engage_item_id(entity_type: EntityType, entity_id: int) -> int:
    return ENGAGE_ITEM_OFFSETS[entity_type] + int(entity_id)


def _decode_engage_item_id(item_id: int) -> tuple[EntityType, int]:
    if item_id >= ENGAGE_ITEM_OFFSETS["activity"]:
        return "activity", item_id - ENGAGE_ITEM_OFFSETS["activity"]
    if item_id >= ENGAGE_ITEM_OFFSETS["program"]:
        return "program", item_id - ENGAGE_ITEM_OFFSETS["program"]
    return "event", item_id


def _ensure_active_qr_code(
    conn,
    entity_type: EntityType,
    entity_id: int,
    created_by_user_id: int,
) -> int:
    now = datetime.now()
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT id
            FROM qr_codes
            WHERE entity_type=%s
              AND entity_id=%s
              AND is_active=1
              AND (expires_at IS NULL OR expires_at >= %s)
            ORDER BY id DESC
            LIMIT 1
            """,
            (entity_type, entity_id, now),
        )
        existing = cur.fetchone()
        if existing:
            return int(existing["id"])

        qr_token = uuid.uuid4().hex
        qr_payload = _build_qr_payload(entity_type, entity_id, qr_token)
        cur.execute(
            """
            INSERT INTO qr_codes(entity_type,entity_id,qr_token,qr_payload,is_active,expires_at,created_by)
            VALUES(%s,%s,%s,%s,1,%s,%s)
            """,
            (
                entity_type,
                entity_id,
                qr_token,
                qr_payload,
                now + timedelta(days=30),
                created_by_user_id,
            ),
        )
        return int(cur.lastrowid)


def _format_time_range(starts_at: datetime, ends_at: Optional[datetime]) -> str:
    start_label = starts_at.strftime("%I:%M %p")
    if not ends_at:
        return start_label
    if ends_at.date() != starts_at.date():
        end_label = ends_at.strftime("%I:%M %p (%d %b)")
        return f"{start_label} - {end_label}"
    end_label = ends_at.strftime("%I:%M %p")
    return f"{start_label} - {end_label}"


def _build_qr_payload(entity_type: EntityType, entity_id: int, qr_token: str) -> str:
    base = FRONTEND_BASE_URL or "http://127.0.0.1:5757"
    return f"{base}/qr-join/{qr_token}"


def _fetch_valid_qr_with_entity(conn, qr_token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    now_dt = datetime.now()
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT id,entity_type,entity_id,qr_token,qr_payload,is_active,expires_at
            FROM qr_codes
            WHERE qr_token=%s
            LIMIT 1
            """,
            (qr_token,),
        )
        qr_code = cur.fetchone()
        if not qr_code:
            raise HTTPException(status_code=404, detail="QR code not found")
        if not qr_code["is_active"]:
            raise HTTPException(status_code=409, detail="QR code is inactive")
        if qr_code["expires_at"] and qr_code["expires_at"] < now_dt:
            raise HTTPException(status_code=409, detail="QR code has expired")

        entity_type = str(qr_code["entity_type"])
        entity_id = int(qr_code["entity_id"])
        entity = get_entity(conn, entity_type, entity_id)  # type: ignore[arg-type]
        if not entity:
            raise HTTPException(status_code=404, detail=f"{entity_type} not found")
        if entity["status"] != "active":
            raise HTTPException(status_code=409, detail=f"{entity_type} is inactive")
        starts_at = entity.get("starts_at")
        ends_at = entity.get("ends_at")
        if ends_at and now_dt > ends_at:
            raise HTTPException(status_code=409, detail="QR code is no longer valid for this session")
        if starts_at and now_dt.date() > starts_at.date():
            raise HTTPException(status_code=409, detail="QR code is no longer valid for this session")

    return qr_code, entity


def _attendance_window(
    starts_at: Optional[datetime],
    ends_at: Optional[datetime],
    now_dt: datetime,
    attended: bool,
) -> tuple[bool, str]:
    is_session_day = starts_at.date() == now_dt.date() if starts_at else True
    has_started = starts_at <= now_dt if starts_at else True
    has_ended = ends_at is not None and now_dt > ends_at

    can_join = is_session_day and has_started and not has_ended and not attended

    if attended:
        status = "Joined"
    elif has_ended:
        status = "Closed"
    elif has_started:
        status = "Live"
    else:
        status = "Upcoming"

    return can_join, status


def _build_dashboard_schedule(user_id: int, now_dt: datetime) -> dict[str, Any]:
    days = []
    for offset in range(7):
        date_value = (now_dt + timedelta(days=offset)).date()
        days.append(
            {
                "key": date_value.isoformat(),
                "day": date_value.strftime("%a"),
                "date": date_value.day,
                "active": offset == 0,
            }
        )
    day_keys = {day["key"] for day in days}
    day_window_start = now_dt.replace(hour=0, minute=0, second=0, microsecond=0)
    day_window_end = day_window_start + timedelta(days=len(days))

    schedule_items: list[dict[str, Any]] = []

    conn = db_connect(DB_NAME)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT *
                FROM (
                    SELECT 'event' AS entity_type, id, title, description, location, starts_at, ends_at, max_participants, status FROM events
                    UNION ALL
                    SELECT 'program' AS entity_type, id, title, description, location, starts_at, ends_at, max_participants, status FROM programs
                    UNION ALL
                    SELECT 'activity' AS entity_type, id, title, description, location, starts_at, ends_at, max_participants, status FROM activities
                ) AS modules
                WHERE status='active'
                  AND starts_at >= %s
                  AND starts_at < %s
                ORDER BY starts_at ASC, id ASC
                LIMIT 40
                """,
                (day_window_start, day_window_end),
            )
            module_rows = cur.fetchall()

            attended_keys: set[tuple[str, int]] = set()
            participant_counts: dict[tuple[str, int], int] = {}
            if module_rows:
                clauses = []
                params: list[Any] = [user_id]
                count_params: list[Any] = []
                for row in module_rows:
                    clauses.append("(entity_type=%s AND entity_id=%s)")
                    params.extend([row["entity_type"], int(row["id"])])
                    count_params.extend([row["entity_type"], int(row["id"])])
                cur.execute(
                    f"""
                    SELECT entity_type,entity_id
                    FROM attendance_logs
                    WHERE attendee_user_id=%s AND ({' OR '.join(clauses)})
                    """,
                    params,
                )
                attended_keys = {
                    (str(row["entity_type"]), int(row["entity_id"]))
                    for row in cur.fetchall()
                }
                cur.execute(
                    f"""
                    SELECT entity_type,entity_id,COUNT(*) AS total
                    FROM attendance_logs
                    WHERE {' OR '.join(clauses)}
                    GROUP BY entity_type,entity_id
                    """,
                    count_params,
                )
                participant_counts = {
                    (str(row["entity_type"]), int(row["entity_id"])): int(row["total"])
                    for row in cur.fetchall()
                }

            for row in module_rows:
                starts_at = row["starts_at"]
                ends_at = row["ends_at"]
                if not starts_at:
                    continue

                day_key = starts_at.date().isoformat()
                if day_key not in day_keys:
                    continue

                entity_type = str(row["entity_type"])
                entity_id = int(row["id"])
                participants = participant_counts.get((entity_type, entity_id), 0)
                max_participants = int(row["max_participants"])
                attended = (entity_type, entity_id) in attended_keys
                is_session_day = starts_at.date() == now_dt.date()
                has_started = starts_at <= now_dt
                has_ended = ends_at is not None and ends_at < now_dt
                can_attend = is_session_day and has_started and not has_ended and not attended

                if attended:
                    status = "Attended"
                    status_class = "is-completed"
                elif has_ended:
                    status = "Closed"
                    status_class = "is-completed"
                elif has_started:
                    status = "Live"
                    status_class = "is-confirmed"
                else:
                    status = "Upcoming"
                    status_class = "is-created"

                schedule_items.append(
                    {
                        "id": entity_id,
                        "entity_type": entity_type,
                        "entity_label": entity_type.capitalize(),
                        "title": row["title"],
                        "description": row["description"],
                        "location": row["location"],
                        "participants": participants,
                        "max_participants": max_participants,
                        "starts_at": starts_at.isoformat() if starts_at else None,
                        "ends_at": ends_at.isoformat() if ends_at else None,
                        "day_key": day_key,
                        "day": starts_at.strftime("%a"),
                        "date": starts_at.day,
                        "date_label": starts_at.strftime("%d %b %Y"),
                        "time_label": _format_time_range(starts_at, ends_at),
                        "status": status,
                        "status_class": status_class,
                        "can_attend": can_attend,
                        "attended": attended,
                    }
                )
    finally:
        conn.close()

    return {
        "title": "Upcoming Schedule",
        "month": now_dt.strftime("%b"),
        "days": days,
        "items": schedule_items,
    }


def _first_non_null(rows: list[dict[str, Any]], key: str) -> Optional[float]:
    for row in rows:
        value = row.get(key)
        if value is not None:
            return float(value)
    return None


def _first_non_null_with_time(rows: list[dict[str, Any]], key: str) -> tuple[Optional[float], Optional[str]]:
    for row in rows:
        value = row.get(key)
        if value is None:
            continue
        recorded_at = row.get("recorded_at")
        return float(value), recorded_at.isoformat() if recorded_at else None
    return None, None


app = FastAPI(title="PHPlus Backend", version="2.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup() -> None:
    rebuild_schema(drop_existing=RESET_SCHEMA_ON_START, seed_data=SEED_SAMPLE_DATA)


@app.get("/")
def root():
    if FRONTEND_INDEX_FILE.is_file():
        return FileResponse(FRONTEND_INDEX_FILE)
    return {
        "message": "PHPlus backend is running",
        "run_command": "python main.py",
    }


@app.post("/api/auth/register")
def register(payload: RegisterRequest):
    conn = db_connect(DB_NAME)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE email=%s", (payload.email,))
            if cur.fetchone():
                raise HTTPException(status_code=409, detail="Email already exists")

            name = _normalized_optional_text(payload.name) or payload.email.split("@")[0].replace(".", " ").title()
            cur.execute(
                "INSERT INTO users(email,password_hash,name,role) VALUES(%s,%s,%s,'staff')",
                (payload.email, hash_password(payload.password), name),
            )
            user_id = cur.lastrowid
            cur.execute(
                """
                SELECT
                    id,
                    email,
                    name,
                    role,
                    identification_no,
                    designation,
                    department,
                    dob,
                    race,
                    marital_status,
                    gender,
                    created_at
                FROM users
                WHERE id=%s
                """,
                (user_id,),
            )
            user = cur.fetchone()
        conn.commit()
    finally:
        conn.close()

    token = create_access_token(user_id=user_id)
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": serialize_user_row(user),
    }


@app.post("/api/auth/login")
def login(payload: LoginRequest):
    conn = db_connect(DB_NAME)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    id,
                    email,
                    password_hash,
                    name,
                    role,
                    identification_no,
                    designation,
                    department,
                    dob,
                    race,
                    marital_status,
                    gender,
                    created_at
                FROM users
                WHERE email=%s
                """,
                (payload.email,),
            )
            user = cur.fetchone()
            if not user or not verify_password(payload.password, user["password_hash"]):
                raise HTTPException(status_code=401, detail="Invalid email or password")
    finally:
        conn.close()

    token = create_access_token(user_id=user["id"])
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": serialize_user_row(user),
    }


@app.post("/api/auth/admin-login")
def admin_login(payload: AdminLoginRequest):
    conn = db_connect(DB_NAME)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    id,
                    email,
                    password_hash,
                    name,
                    role,
                    identification_no,
                    designation,
                    department,
                    dob,
                    race,
                    marital_status,
                    gender,
                    created_at
                FROM users
                WHERE role='admin'
                ORDER BY id ASC
                LIMIT 1
                """
            )
            admin_user = cur.fetchone()
            if not admin_user:
                raise HTTPException(status_code=500, detail="Admin account is not configured")
            if not verify_password(payload.password, admin_user["password_hash"]):
                raise HTTPException(status_code=401, detail="Invalid admin password")
    finally:
        conn.close()

    token = create_access_token(user_id=admin_user["id"])
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": serialize_user_row(admin_user),
    }


@app.get("/api/auth/me")
def me(current_user: dict[str, Any] = Depends(get_current_user)):
    return serialize_user_row(current_user)


@app.put("/api/auth/me")
def update_me(payload: UpdateProfileRequest, current_user: dict[str, Any] = Depends(get_current_user)):
    next_name = current_user["name"]
    if "name" in payload.model_fields_set:
        cleaned_name = _normalized_optional_text(payload.name)
        if cleaned_name is None:
            raise HTTPException(status_code=400, detail="Name cannot be empty")
        next_name = cleaned_name

    next_email = current_user["email"]
    if "email" in payload.model_fields_set:
        if payload.email is None:
            raise HTTPException(status_code=400, detail="Email cannot be empty")
        next_email = payload.email

    identification_no = current_user.get("identification_no")
    if "identification_no" in payload.model_fields_set:
        identification_no = _normalized_optional_text(payload.identification_no)

    designation = current_user.get("designation")
    if "designation" in payload.model_fields_set:
        designation = _normalized_optional_text(payload.designation)

    department = current_user.get("department")
    if "department" in payload.model_fields_set:
        department = _normalized_optional_text(payload.department)

    next_dob = current_user.get("dob")
    if "dob" in payload.model_fields_set:
        next_dob = payload.dob

    race = current_user.get("race")
    if "race" in payload.model_fields_set:
        race = _normalized_optional_text(payload.race)

    marital_status = current_user.get("marital_status")
    if "marital_status" in payload.model_fields_set:
        marital_status = _normalized_optional_text(payload.marital_status)

    gender = current_user.get("gender")
    if "gender" in payload.model_fields_set:
        gender = _normalized_optional_text(payload.gender)

    conn = db_connect(DB_NAME)
    try:
        with conn.cursor() as cur:
            if next_email != current_user["email"]:
                cur.execute("SELECT id FROM users WHERE email=%s AND id<>%s", (next_email, current_user["id"]))
                if cur.fetchone():
                    raise HTTPException(status_code=409, detail="Email already exists")

            cur.execute(
                """
                UPDATE users
                SET
                    name=%s,
                    email=%s,
                    identification_no=%s,
                    designation=%s,
                    department=%s,
                    dob=%s,
                    race=%s,
                    marital_status=%s,
                    gender=%s
                WHERE id=%s
                """,
                (
                    next_name,
                    next_email,
                    identification_no,
                    designation,
                    department,
                    next_dob,
                    race,
                    marital_status,
                    gender,
                    current_user["id"],
                ),
            )
            cur.execute(
                """
                SELECT
                    id,
                    email,
                    name,
                    role,
                    identification_no,
                    designation,
                    department,
                    dob,
                    race,
                    marital_status,
                    gender,
                    created_at
                FROM users
                WHERE id=%s
                """,
                (current_user["id"],),
            )
            updated_user = cur.fetchone()
        conn.commit()
    finally:
        conn.close()

    return serialize_user_row(updated_user)


@app.post("/api/auth/change-password")
def change_password(payload: ChangePasswordRequest, current_user: dict[str, Any] = Depends(get_current_user)):
    if payload.current_password == payload.new_password:
        raise HTTPException(status_code=400, detail="New password must be different from current password")

    conn = db_connect(DB_NAME)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT password_hash FROM users WHERE id=%s", (current_user["id"],))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="User not found")
            if not verify_password(payload.current_password, row["password_hash"]):
                raise HTTPException(status_code=400, detail="Current password is incorrect")

            cur.execute(
                "UPDATE users SET password_hash=%s WHERE id=%s",
                (hash_password(payload.new_password), current_user["id"]),
            )
        conn.commit()
    finally:
        conn.close()

    return {"message": "Password updated successfully"}


@app.get("/api/dashboard")
def dashboard(current_user: dict[str, Any] = Depends(get_current_user)):
    user_id = current_user["id"]
    mental_assessments: dict[AssessmentType, dict[str, Any]] = {
        assessment_type: {
            "assessment_type": assessment_type,
            "label": ASSESSMENT_LABELS[assessment_type],
            "score": None,
            "severity": "No Data",
            "recorded_at": None,
        }
        for assessment_type in ASSESSMENT_SEQUENCE
    }
    conn = db_connect(DB_NAME)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT weight_kg,height_cm,systolic_bp,diastolic_bp,recorded_at
                FROM health_records
                WHERE user_id=%s
                ORDER BY recorded_at DESC, id DESC
                LIMIT 60
                """,
                (user_id,),
            )
            health_rows = cur.fetchall()
            mental_assessments = _load_latest_mental_assessments(cur, user_id)
    finally:
        conn.close()

    latest_weight, latest_weight_time = _first_non_null_with_time(health_rows, "weight_kg")
    latest_height, latest_height_time = _first_non_null_with_time(health_rows, "height_cm")

    latest_bp = None
    latest_bp_time = None
    for row in health_rows:
        if row["systolic_bp"] is not None and row["diastolic_bp"] is not None:
            latest_bp = (int(row["systolic_bp"]), int(row["diastolic_bp"]))
            latest_bp_time = row["recorded_at"].isoformat() if row.get("recorded_at") else None
            break

    if latest_weight and latest_height and latest_height > 0:
        bmi_value = latest_weight / ((latest_height / 100) * (latest_height / 100))
    else:
        bmi_value = 23.1

    # Build BMI trend for current year using only actual record points (no carry-forward on empty days/months).
    health_rows_asc = list(reversed(health_rows))
    running_weight = None
    running_height = None
    bmi_events_by_day: dict[tuple[int, int], float] = {}
    month_last_bmi: dict[int, float] = {}
    now_dt = datetime.now()
    current_year = now_dt.year

    for row in health_rows_asc:
        if row["weight_kg"] is not None:
            running_weight = float(row["weight_kg"])
        if row["height_cm"] is not None:
            running_height = float(row["height_cm"])
        if running_weight and running_height and running_height > 0:
            bmi = running_weight / ((running_height / 100) * (running_height / 100))
            dt = row.get("recorded_at")
            if not dt:
                continue
            rounded_bmi = round(float(bmi), 2)
            if dt.year == current_year:
                bmi_events_by_day[(dt.month, dt.day)] = rounded_bmi
                month_last_bmi[dt.month] = rounded_bmi

    cholesterol = []
    bmi_daily_by_month: dict[str, list[dict[str, Any]]] = {}

    for month_index in range(1, now_dt.month + 1):
        days_in_month = calendar.monthrange(current_year, month_index)[1]
        month_end_day = now_dt.day if month_index == now_dt.month else days_in_month
        month_name = datetime(current_year, month_index, 1).strftime("%b")
        daily_points = []

        for day in range(1, month_end_day + 1):
            event_key = (month_index, day)
            daily_points.append(
                {
                    "day": day,
                    "value": bmi_events_by_day.get(event_key),
                }
            )

        bmi_daily_by_month[month_name] = daily_points
        cholesterol.append(
            {
                "month": month_name,
                "value": month_last_bmi.get(month_index),
            }
        )

    bp_rows_desc = [row for row in health_rows if row["systolic_bp"] is not None and row["diastolic_bp"] is not None]
    bp_rows_asc = list(reversed(bp_rows_desc))
    systolic_series = [float(row["systolic_bp"]) for row in bp_rows_asc[-9:]]
    diastolic_series = [float(row["diastolic_bp"]) for row in bp_rows_asc[-9:]]

    if not systolic_series:
        systolic_series = [132, 122, 124, 112, 116, 121, 118, 122, 121]
        diastolic_series = [84, 80, 79, 76, 78, 80, 79, 80, 81]

    height_text = f"{latest_height:.0f} cm" if latest_height is not None else "--"
    weight_text = f"{latest_weight:.1f} kg" if latest_weight is not None else "--"
    bp_text = f"{latest_bp[0]}/{latest_bp[1]} mmHg" if latest_bp else "--"

    bp_status_label = "No Data"
    bp_status_color = "bp-neutral"
    if latest_bp:
        systolic, diastolic = latest_bp
        if systolic >= 140 or diastolic >= 90:
            bp_status_label = "Hypertension"
            bp_status_color = "bp-red"
        elif systolic >= 120 or diastolic >= 80:
            bp_status_label = "At Risk (Prehypertension)"
            bp_status_color = "bp-yellow"
        else:
            bp_status_label = "Normal"
            bp_status_color = "bp-green"

    schedule_data = _build_dashboard_schedule(user_id=user_id, now_dt=now_dt)
    first_name = current_user["name"].split(" ")[0]
    return {
        "profile": {
            "name": current_user["name"],
            "location": "Kansas",
            "avatar_url": "https://i.pravatar.cc/100?img=32",
            "greeting": f"Hello, {first_name}!",
            "subtitle": "How are you feeling today?",
        },
        "bmi": {
            "value": round(float(bmi_value), 1),
            "healthy_min": 18.5,
            "healthy_max": 24.9,
        },
        "research_cards": [
            {
                "metric_key": "height",
                "label": "Height",
                "value": height_text,
                "class_name": "is-height",
                "last_update": latest_height_time,
            },
            {
                "metric_key": "weight",
                "label": "Weight",
                "value": weight_text,
                "class_name": "is-weight",
                "last_update": latest_weight_time,
            },
            {
                "metric_key": "blood_pressure",
                "label": "Blood Pressure",
                "value": bp_text,
                "class_name": "is-bp",
                "last_update": latest_bp_time,
                "status_label": bp_status_label,
                "status_color": bp_status_color,
            },
        ],
        "cholesterol": cholesterol,
        "bmi_daily_by_month": bmi_daily_by_month,
        "bmi_default_month": datetime(current_year, now_dt.month, 1).strftime("%b"),
        "mental_assessments": mental_assessments,
        "vital_signs": {
            "systolic": systolic_series,
            "diastolic": diastolic_series,
        },
        "medications": [
            {"name": "B12", "dosage": "250 mg", "schedule": "21 Sep - 25 Sep", "highlight": False, "rotate": -36},
            {"name": "Verapamil", "dosage": "480 mg", "schedule": "21 Sep - Until next check-up", "highlight": True, "rotate": 12},
            {"name": "Ibuprofen", "dosage": "400 mg", "schedule": "As needed for pain", "highlight": False, "rotate": -24},
            {"name": "Aspirin", "dosage": "300 mg", "schedule": "21 Sep - 25 Sep", "highlight": False, "rotate": 18},
        ],
        "allergies": ["Penicillins", "Cephalosporins", "Sulfonamides"],
        "schedule": schedule_data,
    }


@app.get("/api/users")
def list_users(
    current_user: dict[str, Any] = Depends(require_admin_user),
):
    _ = current_user
    conn = db_connect(DB_NAME)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    id,
                    email,
                    name,
                    role,
                    identification_no,
                    designation,
                    department,
                    dob,
                    race,
                    marital_status,
                    gender,
                    created_at
                FROM users
                ORDER BY id DESC
                """
            )
            rows = cur.fetchall()
    finally:
        conn.close()

    return [
        {
            "id": row["id"],
            "email": row["email"],
            "name": row["name"],
            "role": row["role"],
            "identification_no": row["identification_no"],
            "designation": row["designation"],
            "department": row["department"],
            "dob": row["dob"].isoformat() if row["dob"] else None,
            "race": row["race"],
            "marital_status": row["marital_status"],
            "gender": row["gender"],
            "created_at": row["created_at"].isoformat() if row["created_at"] else None,
        }
        for row in rows
    ]


@app.post("/api/admin/users/{user_id}/reset-password")
def admin_reset_user_password(
    user_id: int,
    payload: AdminResetPasswordRequest,
    admin_user: dict[str, Any] = Depends(require_admin_user),
):
    _ = admin_user
    if user_id < 1:
        raise HTTPException(status_code=400, detail="Invalid user id")

    conn = db_connect(DB_NAME)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id,role,name FROM users WHERE id=%s", (user_id,))
            target_user = cur.fetchone()
            if not target_user:
                raise HTTPException(status_code=404, detail="User not found")
            if target_user["role"] != "staff":
                raise HTTPException(status_code=400, detail="Only staff password can be reset")

            cur.execute(
                "UPDATE users SET password_hash=%s WHERE id=%s",
                (hash_password(payload.new_password), user_id),
            )
        conn.commit()
    finally:
        conn.close()

    return {
        "message": f"Password reset for {target_user['name']}",
        "user_id": user_id,
    }


@app.get("/api/events")
def list_events(current_user: dict[str, Any] = Depends(get_current_user)):
    _ = current_user
    return fetch_modules("event")


@app.post("/api/events")
def create_event(payload: ModuleCreateRequest, admin_user: dict[str, Any] = Depends(require_admin_user)):
    return create_module("event", payload, creator_id=admin_user["id"])


@app.put("/api/events/{event_id}")
def update_event(event_id: int, payload: ModuleCreateRequest, admin_user: dict[str, Any] = Depends(require_admin_user)):
    _ = admin_user
    return update_module("event", event_id, payload)


@app.delete("/api/events/{event_id}")
def delete_event(event_id: int, admin_user: dict[str, Any] = Depends(require_admin_user)):
    _ = admin_user
    return delete_module("event", event_id)


@app.get("/api/programs")
def list_programs(current_user: dict[str, Any] = Depends(get_current_user)):
    _ = current_user
    return fetch_modules("program")


@app.post("/api/programs")
def create_program(payload: ModuleCreateRequest, admin_user: dict[str, Any] = Depends(require_admin_user)):
    return create_module("program", payload, creator_id=admin_user["id"])


@app.put("/api/programs/{program_id}")
def update_program(
    program_id: int,
    payload: ModuleCreateRequest,
    admin_user: dict[str, Any] = Depends(require_admin_user),
):
    _ = admin_user
    return update_module("program", program_id, payload)


@app.delete("/api/programs/{program_id}")
def delete_program(program_id: int, admin_user: dict[str, Any] = Depends(require_admin_user)):
    _ = admin_user
    return delete_module("program", program_id)


@app.get("/api/activities")
def list_activities(current_user: dict[str, Any] = Depends(get_current_user)):
    _ = current_user
    return fetch_modules("activity")


@app.post("/api/activities")
def create_activity(payload: ModuleCreateRequest, admin_user: dict[str, Any] = Depends(require_admin_user)):
    return create_module("activity", payload, creator_id=admin_user["id"])


@app.put("/api/activities/{activity_id}")
def update_activity(
    activity_id: int,
    payload: ModuleCreateRequest,
    admin_user: dict[str, Any] = Depends(require_admin_user),
):
    _ = admin_user
    return update_module("activity", activity_id, payload)


@app.delete("/api/activities/{activity_id}")
def delete_activity(activity_id: int, admin_user: dict[str, Any] = Depends(require_admin_user)):
    _ = admin_user
    return delete_module("activity", activity_id)


@app.get("/api/engage/categories")
def engage_categories(current_user: dict[str, Any] = Depends(get_current_user)):
    _ = current_user
    now_dt = datetime.now()
    conn = db_connect(DB_NAME)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT COUNT(*) AS total
                FROM events
                WHERE status='active' AND (ends_at IS NULL OR ends_at >= %s)
                """,
                (now_dt,),
            )
            events = int(cur.fetchone()["total"])

            cur.execute(
                """
                SELECT COUNT(*) AS total
                FROM programs
                WHERE status='active' AND (ends_at IS NULL OR ends_at >= %s)
                """,
                (now_dt,),
            )
            programs = int(cur.fetchone()["total"])

            cur.execute(
                """
                SELECT COUNT(*) AS total
                FROM activities
                WHERE status='active' AND (ends_at IS NULL OR ends_at >= %s)
                """,
                (now_dt,),
            )
            activities = int(cur.fetchone()["total"])
    finally:
        conn.close()

    return {
        "events": events,
        "programs": programs,
        "activities": activities,
    }


@app.get("/api/engage/items")
def engage_items(
    type: Optional[EntityType] = Query(default=None),
    current_user: dict[str, Any] = Depends(get_current_user),
):
    now_dt = datetime.now()
    conn = db_connect(DB_NAME)
    try:
        with conn.cursor() as cur:
            query = """
                SELECT *
                FROM (
                    SELECT 'event' AS entity_type, id, title, description, location, starts_at, ends_at, max_participants, status FROM events
                    UNION ALL
                    SELECT 'program' AS entity_type, id, title, description, location, starts_at, ends_at, max_participants, status FROM programs
                    UNION ALL
                    SELECT 'activity' AS entity_type, id, title, description, location, starts_at, ends_at, max_participants, status FROM activities
                ) AS modules
                WHERE status='active'
                  AND (ends_at IS NULL OR ends_at >= %s)
            """
            params: list[Any] = [now_dt]
            if type:
                query += " AND entity_type=%s"
                params.append(type)

            query += " ORDER BY starts_at ASC, id ASC LIMIT 120"
            cur.execute(query, params)
            module_rows = cur.fetchall()

            participant_counts: dict[tuple[str, int], int] = {}
            joined_keys: set[tuple[str, int]] = set()

            if module_rows:
                clauses = []
                count_params: list[Any] = []
                for row in module_rows:
                    clauses.append("(entity_type=%s AND entity_id=%s)")
                    count_params.extend([str(row["entity_type"]), int(row["id"])])

                cur.execute(
                    f"""
                    SELECT entity_type,entity_id,COUNT(*) AS total
                    FROM attendance_logs
                    WHERE {' OR '.join(clauses)}
                    GROUP BY entity_type,entity_id
                    """,
                    count_params,
                )
                participant_counts = {
                    (str(row["entity_type"]), int(row["entity_id"])): int(row["total"])
                    for row in cur.fetchall()
                }

                joined_params: list[Any] = [int(current_user["id"])]
                joined_params.extend(count_params)
                cur.execute(
                    f"""
                    SELECT entity_type,entity_id
                    FROM attendance_logs
                    WHERE attendee_user_id=%s AND ({' OR '.join(clauses)})
                    """,
                    joined_params,
                )
                joined_keys = {
                    (str(row["entity_type"]), int(row["entity_id"]))
                    for row in cur.fetchall()
                }

            items = []
            for row in module_rows:
                starts_at = row.get("starts_at")
                ends_at = row.get("ends_at")
                if not starts_at:
                    continue
                entity_type = str(row["entity_type"])
                entity_id = int(row["id"])
                key = (entity_type, entity_id)
                max_participants = int(row["max_participants"])
                participants = participant_counts.get(key, 0)
                joined = key in joined_keys
                is_session_day = starts_at.date() == now_dt.date()
                has_started = starts_at <= now_dt
                has_ended = ends_at is not None and ends_at < now_dt
                is_full = participants >= max_participants
                can_join = is_session_day and has_started and not has_ended and not joined and not is_full

                if joined:
                    status = "Joined"
                    status_class = "is-confirmed"
                elif is_full:
                    status = "Full"
                    status_class = "is-completed"
                elif has_ended:
                    status = "Closed"
                    status_class = "is-completed"
                elif has_started and is_session_day:
                    status = "Live"
                    status_class = "is-confirmed"
                else:
                    status = "Upcoming"
                    status_class = "is-created"

                items.append(
                    {
                        "id": _encode_engage_item_id(entity_type, entity_id),  # type: ignore[arg-type]
                        "type": entity_type,
                        "title": row["title"],
                        "starts_at": starts_at.isoformat() if starts_at else None,
                        "ends_at": ends_at.isoformat() if ends_at else None,
                        "date": starts_at.strftime("%d %b %Y"),
                        "time": _format_time_range(starts_at, ends_at),
                        "location": row["location"],
                        "participants": participants,
                        "max_participants": max_participants,
                        "description": row["description"],
                        "joined": joined,
                        "is_full": is_full,
                        "can_join": can_join,
                        "status": status,
                        "status_class": status_class,
                    }
                )
            return items
    finally:
        conn.close()


@app.post("/api/engage/items/{item_id}/join")
def join_engage_item(
    item_id: int,
    current_user: dict[str, Any] = Depends(get_current_user),
):
    if item_id < 1:
        raise HTTPException(status_code=400, detail="Invalid item id")

    entity_type, entity_id = _decode_engage_item_id(item_id)
    if entity_id < 1:
        raise HTTPException(status_code=400, detail="Invalid item id")

    now_dt = datetime.now()
    conn = db_connect(DB_NAME)
    try:
        with conn.cursor() as cur:
            entity = get_entity(conn, entity_type, entity_id)
            if not entity:
                raise HTTPException(status_code=404, detail=f"{entity_type} not found")
            if entity["status"] != "active":
                raise HTTPException(status_code=409, detail=f"{entity_type} is inactive")
            starts_at = entity.get("starts_at")
            ends_at = entity.get("ends_at")
            if starts_at and now_dt.date() != starts_at.date():
                raise HTTPException(status_code=409, detail="Attendance is only available on the session date")
            if starts_at and now_dt < starts_at:
                raise HTTPException(status_code=409, detail="Attendance is available when the session starts")
            if ends_at and now_dt > ends_at:
                raise HTTPException(status_code=409, detail="Attendance window has ended")

            cur.execute(
                """
                SELECT id
                FROM attendance_logs
                WHERE entity_type=%s AND entity_id=%s AND attendee_user_id=%s
                LIMIT 1
                """,
                (entity_type, entity_id, current_user["id"]),
            )
            existing = cur.fetchone()
            if existing:
                cur.execute(
                    """
                    SELECT COUNT(*) AS total
                    FROM attendance_logs
                    WHERE entity_type=%s AND entity_id=%s
                    """,
                    (entity_type, entity_id),
                )
                participants = int(cur.fetchone()["total"])
                conn.commit()
                return {
                    "joined": True,
                    "participants": participants,
                }

            cur.execute(
                """
                SELECT COUNT(*) AS total
                FROM attendance_logs
                WHERE entity_type=%s AND entity_id=%s
                """,
                (entity_type, entity_id),
            )
            current_participants = int(cur.fetchone()["total"])
            max_participants = int(entity["max_participants"])
            if current_participants >= max_participants:
                raise HTTPException(status_code=409, detail=f"{entity_type} is full")

            qr_code_id = _ensure_active_qr_code(
                conn=conn,
                entity_type=entity_type,  # type: ignore[arg-type]
                entity_id=entity_id,
                created_by_user_id=current_user["id"],
            )

            try:
                cur.execute(
                    """
                    INSERT INTO attendance_logs
                    (entity_type,entity_id,qr_code_id,attendee_user_id,scanned_by_user_id,status,notes)
                    VALUES(%s,%s,%s,%s,%s,'present',%s)
                    """,
                    (
                        entity_type,
                        entity_id,
                        qr_code_id,
                        current_user["id"],
                        current_user["id"],
                        "Engage join attendance",
                    ),
                )
            except IntegrityError:
                pass

            cur.execute(
                """
                SELECT COUNT(*) AS total
                FROM attendance_logs
                WHERE entity_type=%s AND entity_id=%s
                """,
                (entity_type, entity_id),
            )
            participants = int(cur.fetchone()["total"])
        conn.commit()
    finally:
        conn.close()

    return {
        "joined": True,
        "participants": participants,
    }


@app.delete("/api/engage/items/{item_id}/join")
def leave_engage_item(
    item_id: int,
    current_user: dict[str, Any] = Depends(get_current_user),
):
    _ = (item_id, current_user)
    raise HTTPException(status_code=405, detail="Cancel registration is disabled; attendance is join-only")


@app.post("/api/dashboard/schedule/{entity_type}/{entity_id}/attend")
def attend_schedule_item(
    entity_type: EntityType,
    entity_id: int,
    current_user: dict[str, Any] = Depends(get_current_user),
):
    if entity_id < 1:
        raise HTTPException(status_code=400, detail="Invalid entity id")

    now_dt = datetime.now()
    conn = db_connect(DB_NAME)
    try:
        with conn.cursor() as cur:
            entity = get_entity(conn, entity_type, entity_id)
            if not entity:
                raise HTTPException(status_code=404, detail=f"{entity_type} not found")
            if entity["status"] != "active":
                raise HTTPException(status_code=409, detail=f"{entity_type} is inactive")

            starts_at = entity.get("starts_at")
            ends_at = entity.get("ends_at")
            if starts_at and now_dt.date() != starts_at.date():
                raise HTTPException(status_code=409, detail="Attendance is only available on the session date")
            if starts_at and now_dt < starts_at:
                raise HTTPException(status_code=409, detail="Attendance is available when the session starts")
            if ends_at and now_dt > ends_at:
                raise HTTPException(status_code=409, detail="Attendance window has ended")

            qr_code_id = _ensure_active_qr_code(
                conn=conn,
                entity_type=entity_type,
                entity_id=entity_id,
                created_by_user_id=current_user["id"],
            )

            try:
                cur.execute(
                    """
                    INSERT INTO attendance_logs
                    (entity_type,entity_id,qr_code_id,attendee_user_id,scanned_by_user_id,status,notes)
                    VALUES(%s,%s,%s,%s,%s,'present',%s)
                    """,
                    (
                        entity_type,
                        entity_id,
                        qr_code_id,
                        current_user["id"],
                        current_user["id"],
                        "Dashboard attendance",
                    ),
                )
                attendance_id = int(cur.lastrowid)
                conn.commit()
                return {
                    "attendance_id": attendance_id,
                    "entity_type": entity_type,
                    "entity_id": entity_id,
                    "attended": True,
                    "already_attended": False,
                    "message": "Attendance recorded",
                }
            except IntegrityError:
                cur.execute(
                    """
                    SELECT id
                    FROM attendance_logs
                    WHERE entity_type=%s AND entity_id=%s AND attendee_user_id=%s
                    LIMIT 1
                    """,
                    (entity_type, entity_id, current_user["id"]),
                )
                existing = cur.fetchone()
                conn.commit()
                return {
                    "attendance_id": int(existing["id"]) if existing else None,
                    "entity_type": entity_type,
                    "entity_id": entity_id,
                    "attended": True,
                    "already_attended": True,
                    "message": "Already attended",
                }
    finally:
        conn.close()


@app.get("/api/qr-codes/{qr_token}/detail")
def qr_code_detail(
    qr_token: str,
    current_user: Optional[dict[str, Any]] = Depends(get_optional_current_user),
):
    now_dt = datetime.now()
    conn = db_connect(DB_NAME)
    try:
        qr_code, entity = _fetch_valid_qr_with_entity(conn, qr_token)
        entity_type = str(qr_code["entity_type"])
        entity_id = int(qr_code["entity_id"])

        starts_at = entity.get("starts_at")
        ends_at = entity.get("ends_at")

        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT title,description,location,starts_at,ends_at,max_participants,status
                FROM (
                    SELECT 'event' AS entity_type, id, title, description, location, starts_at, ends_at, max_participants, status FROM events
                    UNION ALL
                    SELECT 'program' AS entity_type, id, title, description, location, starts_at, ends_at, max_participants, status FROM programs
                    UNION ALL
                    SELECT 'activity' AS entity_type, id, title, description, location, starts_at, ends_at, max_participants, status FROM activities
                ) AS modules
                WHERE entity_type=%s AND id=%s
                LIMIT 1
                """,
                (entity_type, entity_id),
            )
            module_row = cur.fetchone()
            attended = False
            attendance_id = None
            if current_user:
                cur.execute(
                    """
                    SELECT id
                    FROM attendance_logs
                    WHERE entity_type=%s AND entity_id=%s AND attendee_user_id=%s
                    ORDER BY id DESC
                    LIMIT 1
                    """,
                    (entity_type, entity_id, current_user["id"]),
                )
                existing_attendance = cur.fetchone()
                if existing_attendance:
                    attended = True
                    attendance_id = int(existing_attendance["id"])
        can_join, status = _attendance_window(starts_at, ends_at, now_dt, attended)
    finally:
        conn.close()

    return {
        "qr_token": qr_token,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "title": module_row["title"] if module_row else entity.get("title"),
        "description": module_row["description"] if module_row else "",
        "location": module_row["location"] if module_row else "",
        "starts_at": starts_at.isoformat() if starts_at else None,
        "ends_at": ends_at.isoformat() if ends_at else None,
        "max_participants": int(module_row["max_participants"]) if module_row else int(entity.get("max_participants", 0) or 0),
        "attended": attended,
        "attendance_id": attendance_id,
        "can_join": can_join,
        "status": status,
    }


@app.post("/api/qr-codes/{qr_token}/join")
def join_via_qr(
    qr_token: str,
    current_user: dict[str, Any] = Depends(get_current_user),
):
    now_dt = datetime.now()
    conn = db_connect(DB_NAME)
    try:
        qr_code, entity = _fetch_valid_qr_with_entity(conn, qr_token)
        entity_type = str(qr_code["entity_type"])
        entity_id = int(qr_code["entity_id"])
        starts_at = entity.get("starts_at")
        ends_at = entity.get("ends_at")

        if starts_at and now_dt.date() != starts_at.date():
            raise HTTPException(status_code=409, detail="Attendance is only available on the session date")
        if starts_at and now_dt < starts_at:
            raise HTTPException(status_code=409, detail="Attendance is available when the session starts")
        if ends_at and now_dt > ends_at:
            raise HTTPException(status_code=409, detail="Attendance window has ended")

        with conn.cursor() as cur:
            try:
                cur.execute(
                    """
                    INSERT INTO attendance_logs
                    (entity_type,entity_id,qr_code_id,attendee_user_id,scanned_by_user_id,status,notes)
                    VALUES(%s,%s,%s,%s,%s,'present',%s)
                    """,
                    (
                        entity_type,
                        entity_id,
                        int(qr_code["id"]),
                        current_user["id"],
                        current_user["id"],
                        "QR join attendance",
                    ),
                )
                attendance_id = int(cur.lastrowid)
                conn.commit()
                return {
                    "attendance_id": attendance_id,
                    "entity_type": entity_type,
                    "entity_id": entity_id,
                    "attended": True,
                    "already_attended": False,
                    "message": "Attendance recorded",
                }
            except IntegrityError:
                cur.execute(
                    """
                    SELECT id
                    FROM attendance_logs
                    WHERE entity_type=%s AND entity_id=%s AND attendee_user_id=%s
                    LIMIT 1
                    """,
                    (entity_type, entity_id, current_user["id"]),
                )
                existing = cur.fetchone()
                conn.commit()
                return {
                    "attendance_id": int(existing["id"]) if existing else None,
                    "entity_type": entity_type,
                    "entity_id": entity_id,
                    "attended": True,
                    "already_attended": True,
                    "message": "Already attended",
                }
    finally:
        conn.close()


@app.post("/api/qr-codes/generate")
def generate_qr_code(
    payload: QRCodeCreateRequest,
    staff_user: dict[str, Any] = Depends(require_admin_user),
):
    conn = db_connect(DB_NAME)
    try:
        with conn.cursor() as cur:
            entity = get_entity(conn, payload.entity_type, payload.entity_id)
            if not entity:
                raise HTTPException(status_code=404, detail=f"{payload.entity_type} not found")

            if entity["status"] != "active":
                raise HTTPException(status_code=409, detail=f"{payload.entity_type} is inactive")

            expires_at = None
            if payload.expires_in_hours is not None:
                expires_at = datetime.now() + timedelta(hours=payload.expires_in_hours)

            qr_token = uuid.uuid4().hex
            qr_payload = _build_qr_payload(payload.entity_type, payload.entity_id, qr_token)

            cur.execute(
                """
                INSERT INTO qr_codes(entity_type,entity_id,qr_token,qr_payload,is_active,expires_at,created_by)
                VALUES(%s,%s,%s,%s,1,%s,%s)
                """,
                (
                    payload.entity_type,
                    payload.entity_id,
                    qr_token,
                    qr_payload,
                    expires_at,
                    staff_user["id"],
                ),
            )
            qr_id = cur.lastrowid
        conn.commit()
        return {
            "id": qr_id,
            "entity_type": payload.entity_type,
            "entity_id": payload.entity_id,
            "qr_token": qr_token,
            "qr_payload": qr_payload,
            "expires_at": expires_at.isoformat() if expires_at else None,
            "is_active": True,
        }
    finally:
        conn.close()


@app.get("/api/qr-codes")
def list_qr_codes(
    entity_type: Optional[EntityType] = Query(default=None),
    entity_id: Optional[int] = Query(default=None, ge=1),
    active_only: bool = Query(default=False),
    current_user: dict[str, Any] = Depends(require_admin_user),
):
    _ = current_user
    conn = db_connect(DB_NAME)
    try:
        with conn.cursor() as cur:
            where = []
            params: list[Any] = []

            if entity_type:
                where.append("entity_type=%s")
                params.append(entity_type)
            if entity_id:
                where.append("entity_id=%s")
                params.append(entity_id)
            if active_only:
                where.append("is_active=1")

            where_sql = f"WHERE {' AND '.join(where)}" if where else ""
            cur.execute(
                f"""
                SELECT id,entity_type,entity_id,qr_token,qr_payload,is_active,expires_at,created_by,created_at
                FROM qr_codes
                {where_sql}
                ORDER BY id DESC
                """,
                params,
            )
            rows = cur.fetchall()
    finally:
        conn.close()

    return [
        {
            "id": row["id"],
            "entity_type": row["entity_type"],
            "entity_id": row["entity_id"],
            "qr_token": row["qr_token"],
            "qr_payload": row["qr_payload"],
            "is_active": bool(row["is_active"]),
            "expires_at": row["expires_at"].isoformat() if row["expires_at"] else None,
            "created_by": row["created_by"],
            "created_at": row["created_at"].isoformat() if row["created_at"] else None,
        }
        for row in rows
    ]


@app.post("/api/attendance/scan")
def scan_attendance(
    payload: AttendanceScanRequest,
    staff_user: dict[str, Any] = Depends(require_staff_user),
):
    if payload.status not in ATTENDANCE_STATUSES:
        raise HTTPException(status_code=400, detail="Invalid attendance status")

    conn = db_connect(DB_NAME)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id,entity_type,entity_id,is_active,expires_at
                FROM qr_codes
                WHERE qr_token=%s
                """,
                (payload.qr_token,),
            )
            qr_code = cur.fetchone()
            if not qr_code:
                raise HTTPException(status_code=404, detail="QR code not found")

            if not qr_code["is_active"]:
                raise HTTPException(status_code=409, detail="QR code is inactive")

            if qr_code["expires_at"] and qr_code["expires_at"] < datetime.now():
                raise HTTPException(status_code=409, detail="QR code has expired")

            cur.execute("SELECT id FROM users WHERE id=%s", (payload.attendee_user_id,))
            attendee = cur.fetchone()
            if not attendee:
                raise HTTPException(status_code=404, detail="Attendee user not found")

            try:
                cur.execute(
                    """
                    INSERT INTO attendance_logs
                    (entity_type,entity_id,qr_code_id,attendee_user_id,scanned_by_user_id,status,notes)
                    VALUES(%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (
                        qr_code["entity_type"],
                        qr_code["entity_id"],
                        qr_code["id"],
                        payload.attendee_user_id,
                        staff_user["id"],
                        payload.status,
                        payload.notes,
                    ),
                )
            except IntegrityError:
                raise HTTPException(status_code=409, detail="Attendance already recorded for this user")

            attendance_id = cur.lastrowid
        conn.commit()
        return {
            "id": attendance_id,
            "entity_type": qr_code["entity_type"],
            "entity_id": qr_code["entity_id"],
            "attendee_user_id": payload.attendee_user_id,
            "scanned_by_user_id": staff_user["id"],
            "status": payload.status,
            "message": "Attendance recorded",
        }
    finally:
        conn.close()


@app.get("/api/attendance-logs")
def get_attendance_logs(
    entity_type: Optional[EntityType] = Query(default=None),
    entity_id: Optional[int] = Query(default=None, ge=1),
    attendee_user_id: Optional[int] = Query(default=None, ge=1),
    limit: int = Query(default=200, ge=1, le=1000),
    current_user: dict[str, Any] = Depends(require_admin_user),
):
    _ = current_user
    effective_attendee_id = attendee_user_id

    conn = db_connect(DB_NAME)
    try:
        with conn.cursor() as cur:
            where = []
            params: list[Any] = []

            if entity_type:
                where.append("al.entity_type=%s")
                params.append(entity_type)
            if entity_id:
                where.append("al.entity_id=%s")
                params.append(entity_id)
            if effective_attendee_id:
                where.append("al.attendee_user_id=%s")
                params.append(effective_attendee_id)

            where_sql = f"WHERE {' AND '.join(where)}" if where else ""
            params.append(limit)

            cur.execute(
                f"""
                SELECT
                    al.id,
                    al.entity_type,
                    al.entity_id,
                    al.status,
                    al.notes,
                    al.scanned_at,
                    al.attendee_user_id,
                    attendee.name AS attendee_name,
                    al.scanned_by_user_id,
                    scanner.name AS scanned_by_name
                FROM attendance_logs al
                INNER JOIN users attendee ON attendee.id=al.attendee_user_id
                LEFT JOIN users scanner ON scanner.id=al.scanned_by_user_id
                {where_sql}
                ORDER BY al.scanned_at DESC
                LIMIT %s
                """,
                params,
            )
            rows = cur.fetchall()
    finally:
        conn.close()

    return [
        {
            "id": row["id"],
            "entity_type": row["entity_type"],
            "entity_id": row["entity_id"],
            "status": row["status"],
            "notes": row["notes"],
            "scanned_at": row["scanned_at"].isoformat() if row["scanned_at"] else None,
            "attendee_user_id": row["attendee_user_id"],
            "attendee_name": row["attendee_name"],
            "scanned_by_user_id": row["scanned_by_user_id"],
            "scanned_by_name": row["scanned_by_name"],
        }
        for row in rows
    ]


@app.get("/api/health-screenings")
def get_health_screening_folders(current_user: dict[str, Any] = Depends(get_current_user)):
    user_ic_suffix = _current_user_ic_suffix(current_user)
    if not user_ic_suffix:
        return []

    folders: list[dict[str, Any]] = []
    for folder_path in _list_health_screening_folders():
        result_count = _count_user_results_in_folder(folder_path, user_ic_suffix)
        if result_count < 1:
            continue

        folder_payload = _health_screening_folder_payload(folder_path.name)
        folder_payload["result_count"] = result_count
        folders.append(folder_payload)

    return folders


@app.get("/api/health-screenings/{folder_name}/tests")
def get_health_screening_results(
    folder_name: str,
    current_user: dict[str, Any] = Depends(get_current_user),
):
    user_ic_suffix = _current_user_ic_suffix(current_user)
    if not user_ic_suffix:
        raise HTTPException(status_code=400, detail="Please update your identification number first")

    folder_path = _resolve_health_screening_folder(folder_name)
    result = _find_user_lab_result(folder_path, user_ic_suffix)
    if not result:
        raise HTTPException(status_code=404, detail="No lab result found for your account in this folder")

    return result


@app.post("/api/mental-health-scores")
def create_mental_health_score(
    payload: MentalAssessmentSubmitRequest,
    current_user: dict[str, Any] = Depends(require_admin_user),
):
    target_user_id = payload.user_id or current_user["id"]
    score = int(payload.score)
    max_score = ASSESSMENT_SCORE_LIMITS[payload.assessment_type]
    if score > max_score:
        raise HTTPException(
            status_code=400,
            detail=f"Score for {ASSESSMENT_LABELS[payload.assessment_type]} must be between 0 and {max_score}",
        )
    severity = payload.severity.strip()
    if not severity:
        raise HTTPException(status_code=400, detail="Severity is required")
    answers_payload: dict[str, Any] = {"mode": "manual_total"}

    conn = db_connect(DB_NAME)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE id=%s", (target_user_id,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="Target user not found")

            cur.execute(
                """
                INSERT INTO mental_health_scores
                (user_id,assessment_type,score,severity,answers_json,notes,recorded_by)
                VALUES(%s,%s,%s,%s,%s,%s,%s)
                """,
                (
                    target_user_id,
                    payload.assessment_type,
                    score,
                    severity,
                    json.dumps(answers_payload, separators=(",", ":")),
                    payload.notes,
                    current_user["id"],
                ),
            )
            score_id = cur.lastrowid
            cur.execute(
                """
                SELECT id,user_id,assessment_type,score,severity,answers_json,notes,recorded_by,recorded_at
                FROM mental_health_scores
                WHERE id=%s
                """,
                (score_id,),
            )
            row = cur.fetchone()
        conn.commit()
    finally:
        conn.close()

    try:
        parsed_answers = json.loads(row["answers_json"]) if row["answers_json"] else {}
    except json.JSONDecodeError:
        parsed_answers = {}

    return {
        "id": row["id"],
        "user_id": row["user_id"],
        "assessment_type": row["assessment_type"],
        "label": ASSESSMENT_LABELS[row["assessment_type"]],
        "score": int(row["score"]),
        "severity": row["severity"],
        "answers": parsed_answers,
        "notes": row["notes"],
        "recorded_by": row["recorded_by"],
        "recorded_at": row["recorded_at"].isoformat() if row["recorded_at"] else None,
    }


@app.get("/api/mental-health-scores")
def get_mental_health_scores(
    assessment_type: Optional[AssessmentType] = Query(default=None),
    user_id: Optional[int] = Query(default=None, ge=1),
    limit: int = Query(default=100, ge=1, le=1000),
    current_user: dict[str, Any] = Depends(get_current_user),
):
    target_user_id = user_id or current_user["id"]
    if target_user_id != current_user["id"] and current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="You can only read scores for your own account")

    conn = db_connect(DB_NAME)
    try:
        with conn.cursor() as cur:
            query = """
                SELECT id,user_id,assessment_type,score,severity,answers_json,notes,recorded_by,recorded_at
                FROM mental_health_scores
                WHERE user_id=%s
            """
            params: list[Any] = [target_user_id]
            if assessment_type:
                query += " AND assessment_type=%s"
                params.append(assessment_type)
            query += " ORDER BY recorded_at DESC, id DESC LIMIT %s"
            params.append(limit)
            cur.execute(query, tuple(params))
            rows = cur.fetchall()
    finally:
        conn.close()

    response_rows = []
    for row in rows:
        try:
            parsed_answers = json.loads(row["answers_json"]) if row["answers_json"] else {}
        except json.JSONDecodeError:
            parsed_answers = {}

        response_rows.append(
            {
                "id": row["id"],
                "user_id": row["user_id"],
                "assessment_type": row["assessment_type"],
                "label": ASSESSMENT_LABELS[row["assessment_type"]],
                "score": int(row["score"]),
                "severity": row["severity"],
                "answers": parsed_answers,
                "notes": row["notes"],
                "recorded_by": row["recorded_by"],
                "recorded_at": row["recorded_at"].isoformat() if row["recorded_at"] else None,
            }
        )

    return response_rows


@app.post("/api/health-records")
def create_health_record(
    payload: HealthRecordCreateRequest,
    current_user: dict[str, Any] = Depends(get_current_user),
):
    target_user_id = payload.user_id or current_user["id"]

    conn = db_connect(DB_NAME)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE id=%s", (target_user_id,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="Target user not found")

            cur.execute(
                """
                INSERT INTO health_records
                (user_id,recorded_by,weight_kg,height_cm,systolic_bp,diastolic_bp,notes)
                VALUES(%s,%s,%s,%s,%s,%s,%s)
                """,
                (
                    target_user_id,
                    current_user["id"],
                    payload.weight_kg,
                    payload.height_cm,
                    payload.systolic_bp,
                    payload.diastolic_bp,
                    payload.notes,
                ),
            )
            record_id = cur.lastrowid
            cur.execute(
                """
                SELECT id,user_id,recorded_by,weight_kg,height_cm,systolic_bp,diastolic_bp,notes,recorded_at
                FROM health_records
                WHERE id=%s
                """,
                (record_id,),
            )
            record = cur.fetchone()
        conn.commit()
    finally:
        conn.close()

    return {
        "id": record["id"],
        "user_id": record["user_id"],
        "recorded_by": record["recorded_by"],
        "weight_kg": float(record["weight_kg"]) if record["weight_kg"] is not None else None,
        "height_cm": float(record["height_cm"]) if record["height_cm"] is not None else None,
        "systolic_bp": record["systolic_bp"],
        "diastolic_bp": record["diastolic_bp"],
        "notes": record["notes"],
        "recorded_at": record["recorded_at"].isoformat() if record["recorded_at"] else None,
    }


@app.get("/api/health-records")
def get_health_records(
    user_id: Optional[int] = Query(default=None, ge=1),
    limit: int = Query(default=100, ge=1, le=1000),
    current_user: dict[str, Any] = Depends(get_current_user),
):
    target_user_id = user_id
    if target_user_id is None:
        target_user_id = current_user["id"]

    conn = db_connect(DB_NAME)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    hr.id,
                    hr.user_id,
                    target.name AS user_name,
                    hr.recorded_by,
                    recorder.name AS recorded_by_name,
                    hr.weight_kg,
                    hr.height_cm,
                    hr.systolic_bp,
                    hr.diastolic_bp,
                    hr.notes,
                    hr.recorded_at
                FROM health_records hr
                INNER JOIN users target ON target.id=hr.user_id
                LEFT JOIN users recorder ON recorder.id=hr.recorded_by
                WHERE hr.user_id=%s
                ORDER BY hr.recorded_at DESC
                LIMIT %s
                """,
                (target_user_id, limit),
            )
            rows = cur.fetchall()
    finally:
        conn.close()

    return [
        {
            "id": row["id"],
            "user_id": row["user_id"],
            "user_name": row["user_name"],
            "recorded_by": row["recorded_by"],
            "recorded_by_name": row["recorded_by_name"],
            "weight_kg": float(row["weight_kg"]) if row["weight_kg"] is not None else None,
            "height_cm": float(row["height_cm"]) if row["height_cm"] is not None else None,
            "systolic_bp": row["systolic_bp"],
            "diastolic_bp": row["diastolic_bp"],
            "notes": row["notes"],
            "recorded_at": row["recorded_at"].isoformat() if row["recorded_at"] else None,
        }
        for row in rows
    ]


@app.get("/{full_path:path}", include_in_schema=False)
def serve_frontend_app(full_path: str):
    if full_path.startswith("api"):
        raise HTTPException(status_code=404, detail="Not found")
    if not FRONTEND_INDEX_FILE.is_file():
        raise HTTPException(status_code=404, detail="Not found")

    resolved_dist = FRONTEND_DIST_DIR.resolve()
    requested_path = (resolved_dist / full_path).resolve()
    try:
        requested_path.relative_to(resolved_dist)
    except ValueError:
        raise HTTPException(status_code=404, detail="Not found")

    if requested_path.is_file():
        return FileResponse(requested_path)
    return FileResponse(FRONTEND_INDEX_FILE)


def run() -> None:
    import uvicorn

    uvicorn.run("main:app", host=APP_HOST, port=APP_PORT, reload=APP_RELOAD)


if __name__ == "__main__":
    run()
