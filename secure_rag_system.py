from typing import Dict, List, Optional, Union, Tuple
import hashlib
import sqlite3
import os
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum
import json
import secrets
import deeplake
import openai
import jwt
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity
from typing import List
from datetime import datetime
import openai
import deeplake
from llama_index import VectorStoreIndex, StorageContext
from llama_index.vector_stores.deeplake import DeepLakeVectorStore
from llama_index.embeddings.openai import OpenAIEmbedding
from sqlalchemy import create_engine, Column, Integer, String, LargeBinary, DateTime, JSON
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.exc import SQLAlchemyError
from dotenv import load_dotenv
load_dotenv()

class UserRole(Enum):
    ADMIN = "admin"
    DEPARTMENT_HEAD = "department_head"  # New role for department managers
    EMPLOYEE = "employee"  # Renamed from DEPARTMENT_USER for clarity

class FileStatus(Enum):
    ACTIVE = "active"
    PENDING_DELETE = "pending_delete"
    DELETED = "deleted"

@dataclass
class User:
    username: str
    department: str
    role: UserRole
    password_hash: str
    created_at: datetime

@dataclass
class FileRecord:
    id: int
    filename: str
    department: str
    uploaded_by: str
    upload_date: datetime
    status: FileStatus
    vector_ids: List[str]
    file_path: str

@dataclass
class DocumentChunk:
    id: str
    content: str
    embedding: List[float]
    metadata: Dict
    department: str

@dataclass
class SearchResult:
    content: str
    source: str
    relevance_score: float
    department: str
    file_id: Optional[int] = None

class SecurityManager:
    def __init__(self, db_path: str = "secure_rag.db"):
        self.db_path = db_path
        self.secret_key = os.getenv("JWT_SECRET_KEY", "your-secret-key-change-this")
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database for user management and file tracking"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Users table - updated with new role system
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                department TEXT NOT NULL,
                role TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_by TEXT,
                is_active INTEGER DEFAULT 1
            )
        ''')
        
        # Files table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                department TEXT NOT NULL,
                uploaded_by TEXT NOT NULL,
                upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'active',
                vector_ids TEXT,
                file_path TEXT NOT NULL,
                FOREIGN KEY (uploaded_by) REFERENCES users (username)
            )
        ''')
        
        # Document chunks table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS document_chunks (
                id TEXT PRIMARY KEY,
                content TEXT NOT NULL,
                embedding TEXT NOT NULL,
                metadata TEXT NOT NULL,
                department TEXT NOT NULL,
                file_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (file_id) REFERENCES files (id)
            )
        ''')
        
        # Delete requests table - enhanced for department head approvals
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS delete_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id INTEGER NOT NULL,
                requested_by TEXT NOT NULL,
                request_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'pending',
                approved_by TEXT,
                approval_date TIMESTAMP,
                admin_response TEXT,
                FOREIGN KEY (file_id) REFERENCES files (id),
                FOREIGN KEY (requested_by) REFERENCES users (username)
            )
        ''')
        
        # Departments table - to manage valid departments
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS departments (
                name TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active INTEGER DEFAULT 1
            )
        ''')
        
        conn.commit()
        conn.close()
        
        # Create default departments and admin
        self.setup_default_data()
    
    def setup_default_data(self):
        """Setup default departments and admin user"""
        # Create default departments
        departments = [
            ("marketing", "Marketing Department"),
            ("sales", "Sales Department"),
            ("admin_department", "Administration")
        ]
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for dept_name, display_name in departments:
            cursor.execute('''
                INSERT OR IGNORE INTO departments (name, display_name)
                VALUES (?, ?)
            ''', (dept_name, display_name))
        
        conn.commit()
        conn.close()
        
        # Create admin user from environment variables
        self.create_admin_from_env()
    
    def create_admin_from_env(self):
        """Create admin user ONLY from environment variables"""
        admin_username = os.getenv("ADMIN_USERNAME")
        admin_password = os.getenv("ADMIN_PASSWORD")
        
        if not admin_username or not admin_password:
            print("⚠️  WARNING: ADMIN_USERNAME or ADMIN_PASSWORD not set in environment")
            return
            
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT username FROM users WHERE username = ?", (admin_username,))
            if cursor.fetchone():
                print(f"ℹ️  Admin user '{admin_username}' already exists")
                conn.close()
                return
            conn.close()
            
            success = self.register_user(admin_username, "admin_department", admin_password, UserRole.ADMIN)
            if success:
                print(f"✅ Admin user created: {admin_username}")
            else:
                print(f"❌ Failed to create admin user: {admin_username}")
                
        except Exception as e:
            print(f"❌ Admin user creation error: {e}")
    
    def hash_password(self, password: str) -> str:
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def get_departments(self) -> List[Dict]:
        """Get all active departments"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT name, display_name FROM departments WHERE is_active = 1")
        departments = [{"name": row[0], "display_name": row[1]} for row in cursor.fetchall()]
        conn.close()
        return departments
    
    def register_user(self, username: str, department: str, password: str, role: UserRole, created_by: str = None) -> bool:
        """Register a new user"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Validate department exists
            cursor.execute("SELECT name FROM departments WHERE name = ? AND is_active = 1", (department,))
            if not cursor.fetchone():
                return False
            
            password_hash = self.hash_password(password)
            cursor.execute('''
                INSERT INTO users (username, department, role, password_hash, created_by)
                VALUES (?, ?, ?, ?, ?)
            ''', (username, department, role.value, password_hash, created_by))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()
    
    def authenticate(self, username: str, password: str) -> Optional[User]:
        """Authenticate user and return User object"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        password_hash = self.hash_password(password)
        cursor.execute('''
            SELECT username, department, role, password_hash, created_at
            FROM users WHERE username = ? AND password_hash = ? AND is_active = 1
        ''', (username, password_hash))
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return User(
                username=result[0],
                department=result[1],
                role=UserRole(result[2]),
                password_hash=result[3],
                created_at=datetime.fromisoformat(result[4])
            )
        return None
    
    def can_delete_file(self, user_role: str, user_department: str, file_department: str, file_uploader: str, username: str) -> bool:
        """Check if user can delete a specific file"""
        # Admin can delete any file
        if user_role == "admin":
            return True
        
        # Department head can delete files in their department
        if user_role == "department_head" and user_department == file_department:
            return True
        
        # Users can only delete their own files
        if file_uploader == username:
            return True
        
        return False
    
    def can_approve_deletion(self, user_role: str, user_department: str, file_department: str) -> bool:
        """Check if user can approve deletion requests"""
        # Admin can approve any deletion
        if user_role == "admin":
            return True
        
        # Department head can approve deletions in their department
        if user_role == "department_head" and user_department == file_department:
            return True
        
        return False
    
    def get_users_in_department(self, department: str) -> List[Dict]:
        """Get all users in a specific department"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT username, role, created_at 
            FROM users 
            WHERE department = ? AND is_active = 1
            ORDER BY role DESC, username
        ''', (department,))
        
        users = []
        for row in cursor.fetchall():
            users.append({
                "username": row[0],
                "role": row[1],
                "created_at": row[2]
            })
        
        conn.close()
        return users
    
    def generate_token(self, user: User) -> str:
        """Generate JWT token for authenticated user"""
        payload = {
            'username': user.username,
            'department': user.department,
            'role': user.role.value,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }
        return jwt.encode(payload, self.secret_key, algorithm='HS256')
    
    def verify_token(self, token: str) -> Optional[Dict]:
        """Verify JWT token and return payload"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    # ADD THESE METHODS TO YOUR SecurityManager CLASS

    def register_user_with_details(self, username: str, department: str, password: str, role: UserRole, created_by: str = None, full_name: str = "") -> bool:
        """Register a new user with additional details"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # First, update the users table to include full_name if it doesn't exist
            cursor.execute("PRAGMA table_info(users)")
            columns = [column[1] for column in cursor.fetchall()]
            if 'full_name' not in columns:
                cursor.execute("ALTER TABLE users ADD COLUMN full_name TEXT DEFAULT ''")
            
            # Validate department exists
            cursor.execute("SELECT name FROM departments WHERE name = ? AND is_active = 1", (department,))
            if not cursor.fetchone():
                return False
            
            password_hash = self.hash_password(password)
            cursor.execute('''
                INSERT INTO users (username, department, role, password_hash, created_by, full_name)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (username, department, role.value, password_hash, created_by, full_name))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()

    def get_employees_in_department(self, department: str) -> List[Dict]:
        """Get all employees (role=employee) in a specific department"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Check if full_name column exists
        cursor.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cursor.fetchall()]
        has_full_name = 'full_name' in columns
        
        if has_full_name:
            cursor.execute('''
                SELECT username, full_name, created_at, created_by
                FROM users 
                WHERE department = ? AND role = 'employee' AND is_active = 1
                ORDER BY created_at DESC
            ''', (department,))
            
            employees = []
            for row in cursor.fetchall():
                employees.append({
                    "username": row[0],
                    "full_name": row[1] or "",
                    "created_at": row[2],
                    "created_by": row[3]
                })
        else:
            cursor.execute('''
                SELECT username, created_at, created_by
                FROM users 
                WHERE department = ? AND role = 'employee' AND is_active = 1
                ORDER BY created_at DESC
            ''', (department,))
            
            employees = []
            for row in cursor.fetchall():
                employees.append({
                    "username": row[0],
                    "full_name": "",
                    "created_at": row[1],
                    "created_by": row[2]
                })
        
        conn.close()
        return employees

    def can_access_file(self, user_role: str, user_department: str, file_department: str) -> bool:
        """Check if user can access (download) a specific file"""
        # Admin can access any file
        if user_role == "admin":
            return True
        
        # Users can only access files in their department
        return user_department == file_department

    def get_user_permissions(self, role: str) -> Dict:
        """Get permissions based on user role"""
        permissions = {
            "admin": {
                "can_upload": True,
                "can_download": True,
                "can_delete_any_file": True,
                "can_create_department_heads": True,
                "can_create_employees": True,
                "can_approve_deletions": True,
                "can_see_all_departments": True
            },
            "department_head": {
                "can_upload": True,
                "can_download": True,
                "can_delete_department_files": True,
                "can_create_employees": True,
                "can_approve_deletions": True,
                "can_see_department_only": True
            },
            "employee": {
                "can_upload": True,
                "can_download": True,
                "can_delete_own_files": True,
                "can_create_employees": False,
                "can_approve_deletions": False,
                "can_see_department_only": True
            }
        }
        
        return permissions.get(role, permissions["employee"])

    # ADD THESE METHODS TO YOUR SecureRAGSystem CLASS

    def create_employee_with_details(self, token: str, username: str, password: str, employee_name: str = "") -> Dict:
        """Department head or admin creates employee with additional details"""
        payload = self.security_manager.verify_token(token)
        if not payload:
            return {"success": False, "error": "Token không hợp lệ"}
        
        # Admin can create employees in any department
        # Department heads can only create employees in their department
        if payload['role'] not in ['admin', 'department_head']:
            return {"success": False, "error": "Không có quyền tạo nhân viên"}
        
        department = payload['department']
        
        # For admin, they might specify department, otherwise use their department
        if payload['role'] == 'admin' and 'target_department' in payload:
            department = payload['target_department']
        
        success = self.security_manager.register_user_with_details(
            username, department, password, UserRole.EMPLOYEE, payload['username'], employee_name
        )
        
        if success:
            return {
                "success": True, 
                "message": f"Tạo tài khoản nhân viên {username} thành công trong phòng ban {department}",
                "employee": {
                    "username": username,
                    "department": department,
                    "role": "employee",
                    "created_by": payload['username']
                }
            }
        return {"success": False, "error": "Không thể tạo tài khoản nhân viên. Tên đăng nhập có thể đã tồn tại."}

    def get_department_employees(self, token: str) -> Dict:
        """Get all employees in the same department (for department heads and admins)"""
        payload = self.security_manager.verify_token(token)
        if not payload:
            return {"success": False, "error": "Token không hợp lệ"}
        
        if payload['role'] not in ['admin', 'department_head']:
            return {"success": False, "error": "Không có quyền xem danh sách nhân viên"}
        
        department = payload['department']
        employees = self.security_manager.get_employees_in_department(department)
        
        return {
            "success": True, 
            "employees": employees,
            "department": department
        }    
# PostgreSQL setup (same as before)
BasePG = declarative_base()

class PGFile(BasePG):
    __tablename__ = "files_pg"
    id = Column(Integer, primary_key=True, autoincrement=True)
    filename = Column(String, nullable=False)
    department = Column(String, nullable=False)
    uploaded_by = Column(String, nullable=False)
    status = Column(String, default="active")
    upload_date = Column(DateTime, default=datetime.utcnow)
    content = Column(LargeBinary, nullable=False)
    vector_ids = Column(JSON, default=[])

DATABASE_URL = os.getenv("DATABASE_URL", None)
engine_pg = None
SessionPG = None

if DATABASE_URL:
    try:
        if DATABASE_URL.startswith("postgres://"):
            DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
            
        engine_pg = create_engine(DATABASE_URL, pool_pre_ping=True)
        SessionPG = sessionmaker(bind=engine_pg)
        
        with engine_pg.connect() as conn:
            conn.execute("SELECT 1")
        
        BasePG.metadata.create_all(bind=engine_pg)
        print(f"✅ Connected to PostgreSQL database successfully")
        
    except Exception as e:
        print(f"❌ PostgreSQL connection failed: {e}")
        engine_pg = None
        SessionPG = None
else:
    print("⚠️  DATABASE_URL not set — using SQLite for file storage")


class FileManager:
    """Enhanced FileManager with role-based access control"""

    def __init__(self, security_manager: SecurityManager, base_path: str = "files"):
        self.security_manager = security_manager
        self.base_path = base_path
        os.makedirs(base_path, exist_ok=True)

    def save_file(self, file_content: bytes, filename: str, department: str, username: str) -> int:
        """Save file bytes to Postgres/local and metadata to SQLite"""
        if not file_content:
            raise ValueError("Uploaded file is empty!")

        pg_id = None
        file_path_val = ""
        
        if DATABASE_URL and SessionPG and engine_pg:
            try:
                session_pg = SessionPG()
                pg_row = PGFile(
                    filename=filename,
                    department=department,
                    uploaded_by=username,
                    content=file_content,
                    status="active"
                )
                session_pg.add(pg_row)
                session_pg.commit()
                session_pg.refresh(pg_row)
                pg_id = int(pg_row.id)
                session_pg.close()
                file_path_val = f"pg:{pg_id}"
                print(f"[DEBUG] Stored bytes in Postgres files_pg id={pg_id}")
            except Exception as e:
                print(f"[ERROR] Postgres save failed: {e}, falling back to local storage")
        
        if not file_path_val:
            try:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                safe_filename = f"{timestamp}_{filename}"
                local_path = os.path.join(self.base_path, safe_filename)
                
                with open(local_path, 'wb') as f:
                    f.write(file_content)
                
                file_path_val = f"local:{safe_filename}"
                print(f"[DEBUG] Stored file locally: {local_path}")
            except Exception as e:
                raise Exception(f"Both Postgres and local storage failed: {e}")
        
        conn = sqlite3.connect(self.security_manager.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO files (filename, department, uploaded_by, file_path, vector_ids)
            VALUES (?, ?, ?, ?, ?)
        ''', (filename, department, username, file_path_val, "[]"))
        file_record_id = cursor.lastrowid
        conn.commit()
        conn.close()

        return file_record_id

    def get_file_record(self, file_id: int) -> Optional[FileRecord]:
        """Get file record from SQLite"""
        conn = sqlite3.connect(self.security_manager.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, filename, department, uploaded_by, upload_date, status, vector_ids, file_path
            FROM files WHERE id = ?
        ''', (file_id,))
        result = cursor.fetchone()
        conn.close()

        if result:
            pg_vector_ids = json.loads(result[6]) if result[6] else []
            upload_date = datetime.fromisoformat(result[4]) if isinstance(result[4], str) else result[4]
            return FileRecord(
                id=result[0],
                filename=result[1],
                department=result[2],
                uploaded_by=result[3],
                upload_date=upload_date,
                status=FileStatus(result[5]) if result[5] in FileStatus._value2member_map_ else FileStatus.ACTIVE,
                vector_ids=pg_vector_ids,
                file_path=result[7]
            )
        return None

    def fetch_file_bytes_from_postgres(self, sqlite_file_record: FileRecord) -> Optional[bytes]:
        """Fetch file bytes from Postgres or local storage"""
        try:
            file_path = sqlite_file_record.file_path or ""
            
            if file_path.startswith("pg:"):
                pg_id = int(file_path.split(":", 1)[1])
                if not SessionPG:
                    return None
                session_pg = SessionPG()
                pg_row = session_pg.query(PGFile).filter(PGFile.id == pg_id).first()
                session_pg.close()
                if not pg_row:
                    return None
                return bytes(pg_row.content)
            
            elif file_path.startswith("local:"):
                local_filename = file_path.split(":", 1)[1]
                local_path = os.path.join(self.base_path, local_filename)
                if not os.path.exists(local_path):
                    return None
                with open(local_path, 'rb') as f:
                    return f.read()
            
            return None
                
        except Exception as e:
            print(f"[ERROR] fetch_file_bytes_from_postgres failed: {e}")
            return None

    def request_file_deletion(self, file_id: int, username: str) -> bool:
        """Create delete request"""
        conn = sqlite3.connect(self.security_manager.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO delete_requests (file_id, requested_by)
                VALUES (?, ?)
            ''', (file_id, username))
            conn.commit()
            return True
        except Exception as e:
            print(f"[ERROR] request_file_deletion failed: {e}")
            return False
        finally:
            conn.close()

    def approve_deletion(self, request_id: int, approver_username: str) -> bool:
        """Approve file deletion (can be admin or department head)"""
        conn = sqlite3.connect(self.security_manager.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute('''
                SELECT file_id FROM delete_requests WHERE id = ? AND status = 'pending'
            ''', (request_id,))
            rr = cursor.fetchone()
            if not rr:
                conn.close()
                return False
            file_id = rr[0]

            rec = self.get_file_record(file_id)
            
            cursor.execute('''
                UPDATE files SET status = 'deleted' WHERE id = ?
            ''', (file_id,))

            cursor.execute('''
                UPDATE delete_requests SET status = 'approved', approved_by = ?, approval_date = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (approver_username, request_id))

            conn.commit()

            # Delete actual file content
            if rec and rec.file_path:
                if rec.file_path.startswith("pg:") and SessionPG:
                    try:
                        pg_id = int(rec.file_path.split(":", 1)[1])
                        session_pg = SessionPG()
                        pg_row = session_pg.query(PGFile).filter(PGFile.id == pg_id).first()
                        if pg_row:
                            session_pg.delete(pg_row)
                            session_pg.commit()
                        session_pg.close()
                    except Exception as e:
                        print(f"[WARN] Could not delete PG file: {e}")
                
                elif rec.file_path.startswith("local:"):
                    try:
                        local_filename = rec.file_path.split(":", 1)[1]
                        local_path = os.path.join(self.base_path, local_filename)
                        if os.path.exists(local_path):
                            os.remove(local_path)
                    except Exception as e:
                        print(f"[WARN] Could not delete local file: {e}")

            return True
        except Exception as e:
            print(f"[ERROR] approve_deletion failed: {e}")
            conn.rollback()
            return False
        finally:
            conn.close()

    def get_pending_deletions_for_department(self, department: str) -> List[Dict]:
        """Get pending deletion requests for a specific department"""
        conn = sqlite3.connect(self.security_manager.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT dr.id, dr.file_id, dr.requested_by, dr.request_date, f.filename, f.department
            FROM delete_requests dr
            JOIN files f ON dr.file_id = f.id
            WHERE dr.status = 'pending' AND f.department = ?
            ORDER BY dr.request_date DESC
        ''', (department,))
        
        requests = []
        for row in cursor.fetchall():
            requests.append({
                "id": row[0],
                "file_id": row[1],
                "requested_by": row[2],
                "request_date": row[3],
                "filename": row[4],
                "department": row[5]
            })
        
        conn.close()
        return requests

# ActiveLoop RAG system (same as before)
class SearchResult:
    def __init__(self, content, source, relevance_score, department, file_id=None):
        self.content = content
        self.source = source
        self.relevance_score = relevance_score
        self.department = department
        self.file_id = file_id

class ActiveLoopRAG:
    def __init__(self, security_manager, file_manager):
        self.security_manager = security_manager
        self.file_manager = file_manager
        
        self.openai_client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        if not os.getenv("OPENAI_API_KEY"):
            raise ValueError("OPENAI_API_KEY environment variable is required")
        
        # Map department names to ActiveLoop datasets
        self.datasets = {
            "marketing": "hub://lemojames101/EPR_Law_marketing",
            "sales": "hub://lemojames101/EPR_Law_sales"  # Updated to match your departments
        }
        
        self.vector_stores = {}
        for dept, path in self.datasets.items():
            try:
                self.vector_stores[dept] = deeplake.load(path, read_only=False)
                print(f"[DEBUG] Loaded dataset for {dept} in read-write mode")
            except Exception as e:
                print(f"[ERROR] Could not load dataset for {dept}: {e}")

    def get_embedding(self, text: str) -> List[float]:
        try:
            response = self.openai_client.embeddings.create(
                input=text,
                model="text-embedding-ada-002"
            )
            return response.data[0].embedding
        except Exception as e:
            print(f"[ERROR] Embedding generation failed: {e}")
            return []

    def search_department(self, query: str, department: str, k: int = 5) -> List[SearchResult]:
        if department not in self.vector_stores:
            print(f"[ERROR] Department {department} not found in vector stores")
            return []

        query_embedding = self.get_embedding(query)
        if not query_embedding:
            return []

        try:
            ds = self.vector_stores[department]
            embeddings = np.stack(ds.embedding[:].numpy())
            texts = ds.text[:].numpy()
            metadatas = ds.metadata[:].numpy()

            sims = np.dot(embeddings, np.array(query_embedding))
            topk_idx = sims.argsort()[-k:][::-1]

            search_results = []
            for idx in topk_idx:
                content = texts[idx].decode('utf-8') if isinstance(texts[idx], bytes) else str(texts[idx])
                
                meta_raw = metadatas[idx]
                if isinstance(meta_raw, bytes):
                    meta = json.loads(meta_raw.decode('utf-8'))
                elif isinstance(meta_raw, str):
                    meta = json.loads(meta_raw)
                else:
                    meta = {}

                score = float(sims[idx])
                search_results.append(SearchResult(
                    content=content,
                    source=meta.get('filename', 'Unknown'),
                    relevance_score=score,
                    department=department,
                    file_id=meta.get('file_id')
                ))

            return search_results

        except Exception as e:
            print(f"[ERROR] Search failed in {department}: {e}")
            return []

    def search_all_accessible(self, query: str, user_department: str, user_role: str, k: int = 5):
        """Search based on user role and department access"""
        if user_role == "admin":
            departments = list(self.vector_stores.keys())
        else:
            departments = [user_department] if user_department in self.vector_stores else []
        
        all_results = []
        for dept in departments:
            all_results.extend(self.search_department(query, dept, k))
        return sorted(all_results, key=lambda x: x.relevance_score, reverse=True)[:k]

    def generate_response(self, query: str, search_results: List[SearchResult]) -> str:
        if not search_results:
            return "Tôi không thể tìm thấy thông tin liên quan nào trong các tài liệu có sẵn."
        
        context = "\n\n".join([
            f"Nguồn: {r.source} (Phòng ban: {r.department})\nNội dung: {r.content}"
            for r in search_results[:3]
        ])
        
        system_prompt = """Bạn là một trợ lý AI hữu ích cho hệ thống cơ sở tri thức của công ty.
        Sử dụng thông tin được cung cấp để trả lời câu hỏi một cách chính xác bằng tiếng Việt.
        Luôn trích dẫn nguồn và phòng ban. Trả lời tự nhiên, dễ hiểu."""

        user_prompt = f"""
Thông tin từ tài liệu công ty:
{context}

Câu hỏi: {query}

Vui lòng cung cấp câu trả lời toàn diện dựa trên thông tin trên bằng tiếng Việt.
"""
        try:
            response = self.openai_client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                max_tokens=800,
                temperature=0.3
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Lỗi khi tạo phản hồi: {e}"

class SecureRAGSystem:
    def __init__(self):
        self.security_manager = SecurityManager()
        self.file_manager = FileManager(self.security_manager)
        self.rag_system = ActiveLoopRAG(self.security_manager, self.file_manager)
    
    def login(self, username: str, password: str) -> Dict:
        """User login"""
        user = self.security_manager.authenticate(username, password)
        if user:
            token = self.security_manager.generate_token(user)
            return {
                "success": True,
                "token": token,
                "user": {
                    "username": user.username,
                    "department": user.department,
                    "role": user.role.value
                },
                "message": "Đăng nhập thành công!"
            }
        return {"success": False, "error": "Thông tin đăng nhập không hợp lệ"}
    
    def create_department_head(self, admin_token: str, username: str, department: str, password: str) -> Dict:
        """Admin creates department head"""
        payload = self.security_manager.verify_token(admin_token)
        if not payload or payload['role'] != 'admin':
            return {"success": False, "error": "Chỉ admin mới có quyền tạo trưởng phòng"}
        
        success = self.security_manager.register_user(
            username, department, password, UserRole.DEPARTMENT_HEAD, payload['username']
        )
        
        if success:
            return {"success": True, "message": f"Tạo trưởng phòng {username} thành công"}
        return {"success": False, "error": "Không thể tạo trưởng phòng"}
    
    def create_employee(self, token: str, username: str, password: str) -> Dict:
        """Department head or admin creates employee"""
        payload = self.security_manager.verify_token(token)
        if not payload:
            return {"success": False, "error": "Token không hợp lệ"}
        
        # Admin can create employees in any department
        # Department heads can only create employees in their department
        if payload['role'] not in ['admin', 'department_head']:
            return {"success": False, "error": "Không có quyền tạo nhân viên"}
        
        department = payload['department']
        success = self.security_manager.register_user(
            username, department, password, UserRole.EMPLOYEE, payload['username']
        )
        
        if success:
            return {"success": True, "message": f"Tạo nhân viên {username} thành công"}
        return {"success": False, "error": "Không thể tạo nhân viên"}
    
    def upload_file(self, token: str, file_content: bytes, filename: str, text_content: Optional[str] = None) -> Dict:
        """Upload file"""
        payload = self.security_manager.verify_token(token)
        if not payload:
            return {"success": False, "error": "Token không hợp lệ"}
        
        department = payload['department']
        username = payload['username']
        
        try:
            file_id = self.file_manager.save_file(file_content, filename, department, username)
            return {
                "success": True,
                "file_id": file_id,
                "message": f"Tải file '{filename}' thành công vào phòng ban {department}"
            }
        except Exception as e:
            return {"success": False, "error": f"Lỗi: {str(e)}"}

    def search(self, token: str, query: str) -> Dict:
        """Search documents based on user role and department"""
        payload = self.security_manager.verify_token(token)
        if not payload:
            return {"success": False, "error": "Token không hợp lệ"}
        
        department = payload['department']
        role = payload['role']
        
        try:
            results = self.rag_system.search_all_accessible(query, department, role)
            response = self.rag_system.generate_response(query, results)
            
            return {
                "success": True,
                "response": response,
                "sources": [
                    {
                        "filename": r.source,
                        "department": r.department,
                        "relevance_score": round(r.relevance_score, 3)
                    } for r in results
                ],
                "query": query
            }
        except Exception as e:
            return {"success": False, "error": f"Lỗi tìm kiếm: {str(e)}"}

    def request_file_deletion(self, token: str, file_id: int) -> Dict:
        """Request file deletion with role-based logic"""
        payload = self.security_manager.verify_token(token)
        if not payload:
            return {"success": False, "error": "Token không hợp lệ"}
        
        # Get file info to check permissions
        file_record = self.file_manager.get_file_record(file_id)
        if not file_record:
            return {"success": False, "error": "File không tồn tại"}
        
        # Check if user can delete this file
        can_delete = self.security_manager.can_delete_file(
            payload['role'], 
            payload['department'], 
            file_record.department,
            file_record.uploaded_by,
            payload['username']
        )
        
        if not can_delete:
            return {"success": False, "error": "Bạn không có quyền xóa file này"}
        
        # Admin and department heads can delete immediately
        if payload['role'] in ['admin', 'department_head']:
            # Create and immediately approve the request
            request_success = self.file_manager.request_file_deletion(file_id, payload['username'])
            if request_success:
                # Get the request ID (assuming it's the latest one for this file)
                conn = sqlite3.connect(self.security_manager.db_path)
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id FROM delete_requests 
                    WHERE file_id = ? AND requested_by = ? AND status = 'pending'
                    ORDER BY id DESC LIMIT 1
                ''', (file_id, payload['username']))
                request_id = cursor.fetchone()[0]
                conn.close()
                
                # Approve immediately
                approve_success = self.file_manager.approve_deletion(request_id, payload['username'])
                if approve_success:
                    return {"success": True, "message": "File đã được xóa thành công"}
                else:
                    return {"success": False, "error": "Không thể xóa file"}
        
        # Regular employees need approval
        success = self.file_manager.request_file_deletion(file_id, payload['username'])
        if success:
            return {"success": True, "message": "Yêu cầu xóa file đã được gửi để phê duyệt"}
        return {"success": False, "error": "Không thể gửi yêu cầu xóa file"}
    
    def get_pending_deletions(self, token: str) -> Dict:
        """Get pending deletion requests based on user role"""
        payload = self.security_manager.verify_token(token)
        if not payload:
            return {"success": False, "error": "Token không hợp lệ"}
        
        if payload['role'] == 'admin':
            # Admin sees all pending deletions
            conn = sqlite3.connect(self.security_manager.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                SELECT dr.id, dr.file_id, dr.requested_by, dr.request_date, f.filename, f.department
                FROM delete_requests dr
                JOIN files f ON dr.file_id = f.id
                WHERE dr.status = 'pending'
                ORDER BY dr.request_date DESC
            ''')
            requests = []
            for row in cursor.fetchall():
                requests.append({
                    "id": row[0],
                    "file_id": row[1],
                    "requested_by": row[2],
                    "request_date": row[3],
                    "filename": row[4],
                    "department": row[5]
                })
            conn.close()
            
        elif payload['role'] == 'department_head':
            # Department head sees only their department's deletions
            requests = self.file_manager.get_pending_deletions_for_department(payload['department'])
            
        else:
            # Regular employees can't see deletion requests
            return {"success": False, "error": "Không có quyền xem yêu cầu xóa file"}
        
        return {"success": True, "requests": requests}
    
    def approve_file_deletion(self, token: str, request_id: int) -> Dict:
        """Approve file deletion (admin or department head)"""
        payload = self.security_manager.verify_token(token)
        if not payload:
            return {"success": False, "error": "Token không hợp lệ"}
        
        if payload['role'] not in ['admin', 'department_head']:
            return {"success": False, "error": "Không có quyền phê duyệt xóa file"}
        
        # Get file info to check department permissions for department heads
        conn = sqlite3.connect(self.security_manager.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT f.department FROM delete_requests dr 
            JOIN files f ON dr.file_id = f.id
            WHERE dr.id = ? AND dr.status = 'pending'
        ''', (request_id,))
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return {"success": False, "error": "Yêu cầu không tồn tại hoặc đã được xử lý"}
        
        file_department = result[0]
        
        # Check if department head has permission for this file
        can_approve = self.security_manager.can_approve_deletion(
            payload['role'], 
            payload['department'], 
            file_department
        )
        
        if not can_approve:
            return {"success": False, "error": "Bạn không có quyền phê duyệt xóa file này"}
        
        success = self.file_manager.approve_deletion(request_id, payload['username'])
        if success:
            return {"success": True, "message": "File đã được xóa thành công"}
        return {"success": False, "error": "Không thể phê duyệt xóa file"}
    
    def get_departments(self, token: str) -> Dict:
        """Get all departments (admin only)"""
        payload = self.security_manager.verify_token(token)
        if not payload or payload['role'] != 'admin':
            return {"success": False, "error": "Chỉ admin mới có quyền xem danh sách phòng ban"}
        
        departments = self.security_manager.get_departments()
        return {"success": True, "departments": departments}
    
    def get_department_users(self, token: str, department: str = None) -> Dict:
        """Get users in department (admin sees all, department head sees their department)"""
        payload = self.security_manager.verify_token(token)
        if not payload:
            return {"success": False, "error": "Token không hợp lệ"}
        
        if payload['role'] == 'admin':
            target_department = department or payload['department']
        elif payload['role'] == 'department_head':
            target_department = payload['department']  # Can only see own department
        else:
            return {"success": False, "error": "Không có quyền xem danh sách nhân viên"}
        
        users = self.security_manager.get_users_in_department(target_department)
        return {"success": True, "users": users, "department": target_department}

# Example usage and setup
if __name__ == "__main__":
    rag_system = SecureRAGSystem()
    
    # Example: Admin creates department heads
    admin_login = rag_system.login("admin_username", "admin_password")
    if admin_login["success"]:
        admin_token = admin_login["token"]
        
        # Create department heads
        rag_system.create_department_head(admin_token, "marketing_head", "marketing", "head_password123")
        rag_system.create_department_head(admin_token, "sales_head", "sales", "head_password123")
        
        print("Department heads created successfully")
    
    # Example: Department head creates employees
    head_login = rag_system.login("marketing_head", "head_password123")
    if head_login["success"]:
        head_token = head_login["token"]
        
        # Create employees in marketing department
        rag_system.create_employee(head_token, "marketing_emp1", "emp_password123")
        rag_system.create_employee(head_token, "marketing_emp2", "emp_password123")
        
        print("Marketing employees created successfully")