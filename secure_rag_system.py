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
    DEPARTMENT_USER = "department_user"

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
    vector_ids: List[str]  # IDs in the vector store
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
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                department TEXT NOT NULL,
                role TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
                vector_ids TEXT,  -- JSON array of vector IDs
                file_path TEXT NOT NULL,
                FOREIGN KEY (uploaded_by) REFERENCES users (username)
            )
        ''')
        
        # Document chunks table for vector storage
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS document_chunks (
                id TEXT PRIMARY KEY,
                content TEXT NOT NULL,
                embedding TEXT NOT NULL,  -- JSON array of embedding vector
                metadata TEXT NOT NULL,   -- JSON metadata
                department TEXT NOT NULL,
                file_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (file_id) REFERENCES files (id)
            )
        ''')
        
        # Delete requests table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS delete_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id INTEGER NOT NULL,
                requested_by TEXT NOT NULL,
                request_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'pending',
                admin_response TEXT,
                FOREIGN KEY (file_id) REFERENCES files (id),
                FOREIGN KEY (requested_by) REFERENCES users (username)
            )
        ''')
        
        conn.commit()
        conn.close()
        
        # Create default admin user if not exists
        self.create_default_admin()
    
    def create_default_admin(self):
        """Create default admin user"""
        try:
            self.register_user("admin", "admin", "admin123", UserRole.ADMIN)
        except:
            pass  # Admin already exists
    
    def hash_password(self, password: str) -> str:
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def register_user(self, username: str, department: str, password: str, role: UserRole) -> bool:
        """Register a new user"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            password_hash = self.hash_password(password)
            cursor.execute('''
                INSERT INTO users (username, department, role, password_hash)
                VALUES (?, ?, ?, ?)
            ''', (username, department, role.value, password_hash))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False  # User already exists
        finally:
            conn.close()
    
    def authenticate(self, username: str, password: str) -> Optional[User]:
        """Authenticate user and return User object"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        password_hash = self.hash_password(password)
        cursor.execute('''
            SELECT username, department, role, password_hash, created_at
            FROM users WHERE username = ? AND password_hash = ?
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

# ---------------------- Postgres-backed FileManager (replace old FileManager) ----------------------
BasePG = declarative_base()

class PGFile(BasePG):
    __tablename__ = "files_pg"
    id = Column(Integer, primary_key=True, autoincrement=True)
    filename = Column(String, nullable=False)
    department = Column(String, nullable=False)
    uploaded_by = Column(String, nullable=False)
    status = Column(String, default="active")   # store as plain string for simplicity
    upload_date = Column(DateTime, default=datetime.utcnow)
    content = Column(LargeBinary, nullable=False)   # raw file bytes
    vector_ids = Column(JSON, default=[])          # optional, kept for convenience

# DB bootstrap for Postgres (engine created from env)
DATABASE_URL = os.getenv("DATABASE_URL", None)
if not DATABASE_URL:
    # For safety: don't crash on import, but warn and set to None
    print("[WARN] DATABASE_URL not set — Postgres file storage will be disabled.")
else:
    engine_pg = create_engine(DATABASE_URL, pool_pre_ping=True)
    SessionPG = sessionmaker(bind=engine_pg)
    try:
        BasePG.metadata.create_all(bind=engine_pg)
    except Exception as e:
        print(f"[WARN] Could not create Postgres tables: {e}")
        engine_pg = None
        SessionPG = None

class FileManager:
    """
    Hybrid FileManager:
      - Stores binary file bytes in Postgres table `files_pg` (if DATABASE_URL configured).
      - Inserts a metadata row into existing SQLite `files` table so the rest of the app can keep using integer file_id.
      - Returns the SQLite file_id (keeps existing behavior).
    """

    def __init__(self, security_manager: SecurityManager, base_path: str = "files"):
        # security_manager still used for SQLite operations (users, delete_requests, old 'files' metadata)
        self.security_manager = security_manager
        self.base_path = base_path  # not used for storage now, kept for compatibility

    def save_file(self, file_content: bytes, filename: str, department: str, username: str) -> int:
        """
        Save file bytes to Postgres and metadata to SQLite.
        """
        if not file_content:
            raise ValueError("Uploaded file is empty!")

        # --- 1) Save raw file into Postgres ---
        pg_id = None
        if DATABASE_URL and SessionPG:
            session_pg = SessionPG()
            pg_row = PGFile(
                filename=filename,
                department=department,
                uploaded_by=username,
                content=file_content,  # ✅ bytes directly here
                status="active"
            )
            session_pg.add(pg_row)
            session_pg.commit()
            session_pg.refresh(pg_row)
            pg_id = int(pg_row.id)
            session_pg.close()
            print(f"[DEBUG] Stored bytes in Postgres files_pg id={pg_id}")
        
        # --- 2) Save metadata into SQLite ---
        conn = sqlite3.connect(self.security_manager.db_path)
        cursor = conn.cursor()
        file_path_val = f"pg:{pg_id}" if pg_id is not None else ""
        cursor.execute('''
            INSERT INTO files (filename, department, uploaded_by, file_path, vector_ids)
            VALUES (?, ?, ?, ?, ?)
        ''', (filename, department, username, file_path_val, "[]"))
        file_record_id = cursor.lastrowid
        conn.commit()
        conn.close()
        print(f"[DEBUG] Created SQLite files record id={file_record_id} (file_path={file_path_val})")

        return file_record_id
    def get_file_record(self, file_id: int) -> Optional[FileRecord]:
        """
        Return a FileRecord dataclass (like the old implementation),
        populated from SQLite `files` metadata. The file_path field will contain the mapping 'pg:<pg_id>' if saved to Postgres.
        """
        conn = sqlite3.connect(self.security_manager.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, filename, department, uploaded_by, upload_date, status, vector_ids, file_path
            FROM files WHERE id = ?
        ''', (file_id,))
        result = cursor.fetchone()
        conn.close()

        if result:
            # Build FileRecord dataclass for compatibility
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
                file_path=result[7]  # contains "pg:<pg_id>" or legacy path
            )
        return None

    def fetch_file_bytes_from_postgres(self, sqlite_file_record: FileRecord) -> Optional[bytes]:
        """
        Given a FileRecord (from get_file_record), return the raw bytes from Postgres (if present).
        """
        try:
            file_path = sqlite_file_record.file_path or ""
            if not file_path.startswith("pg:"):
                return None
            pg_id = int(file_path.split(":", 1)[1])
            if not SessionPG:
                return None
            session_pg = SessionPG()
            pg_row = session_pg.query(PGFile).filter(PGFile.id == pg_id).first()
            session_pg.close()
            if not pg_row:
                return None
            return bytes(pg_row.content)
        except Exception as e:
            print(f"[ERROR] fetch_file_bytes_from_postgres failed: {e}")
            return None

    def update_vector_ids(self, file_id: int, vector_ids: List[str]):
        """Update vector IDs in SQLite 'files' table (keeps previous behavior)"""
        conn = sqlite3.connect(self.security_manager.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE files SET vector_ids = ? WHERE id = ?
        ''', (json.dumps(vector_ids), file_id))
        conn.commit()
        conn.close()

        # also (optionally) update the PG row vector_ids if mapping exists
        try:
            rec = self.get_file_record(file_id)
            if rec and rec.file_path and rec.file_path.startswith("pg:") and SessionPG:
                pg_id = int(rec.file_path.split(":", 1)[1])
                session_pg = SessionPG()
                pg_row = session_pg.query(PGFile).filter(PGFile.id == pg_id).first()
                if pg_row:
                    pg_row.vector_ids = vector_ids
                    session_pg.commit()
                session_pg.close()
        except Exception as e:
            print(f"[WARN] Could not update PG vector_ids: {e}")

    def request_file_deletion(self, file_id: int, username: str) -> bool:
        """Create delete request in SQLite (same as original)"""
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

    def approve_deletion(self, request_id: int, admin_username: str) -> bool:
        """
        Mark SQLite files row as deleted and mark the delete_request approved.
        If the SQLite file has a 'pg:<pg_id>' mapping, also delete the Postgres bytes row.
        """
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

            # Update SQLite files status
            cursor.execute('''
                UPDATE files SET status = 'deleted' WHERE id = ?
            ''', (file_id,))

            # Update delete_requests row
            cursor.execute('''
                UPDATE delete_requests SET status = 'approved', admin_response = ?
                WHERE id = ?
            ''', (f"Approved by {admin_username}", request_id))

            conn.commit()

            # Try deleting from Postgres if mapping exists
            rec = self.get_file_record(file_id)
            if rec and rec.file_path and rec.file_path.startswith("pg:") and SessionPG:
                pg_id = int(rec.file_path.split(":", 1)[1])
                try:
                    session_pg = SessionPG()
                    pg_row = session_pg.query(PGFile).filter(PGFile.id == pg_id).first()
                    if pg_row:
                        session_pg.delete(pg_row)
                        session_pg.commit()
                    session_pg.close()
                except Exception as e:
                    print(f"[WARN] Could not delete PG file id={pg_id}: {e}")

            return True
        except Exception as e:
            print(f"[ERROR] approve_deletion failed: {e}")
            conn.rollback()
            return False
        finally:
            conn.close()
# ------------------------------------------------------------------------------------------------------



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
        
        # OpenAI client
        self.openai_client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        if not os.getenv("OPENAI_API_KEY"):
            raise ValueError("OPENAI_API_KEY environment variable is required")
        
        # ActiveLoop dataset paths
        self.datasets = {
            "marketing": "hub://lemojames101/EPR_Law_marketing",
            "ban_hang": "hub://lemojames101/EPR_Law_sales"
        }
        
        self.vector_stores = {}
        for dept, path in self.datasets.items():
            try:
                # Load in read-write mode if unlocked
                self.vector_stores[dept] = deeplake.load(path, read_only=False)
                print(f"[DEBUG] Loaded dataset for {dept} in read-write mode")
            except Exception as e:
                print(f"[ERROR] Could not load dataset for {dept}: {e}")

    # --- Embedding ---
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

    # --- Add documents ---
    # def add_document(self, text: str, department: str, file_id: int, filename: str):
    #     # if department not in self.vector_stores:
    #     #     print(f"[ERROR] Department {department} not found")
    #     #     return
        
    #     # embedding = self.get_embedding(text)
    #     # if not embedding:
    #     #     return
        
    #     # metadata = {
    #     #     "file_id": file_id,
    #     #     "filename": filename,
    #     #     "department": department,
    #     #     "timestamp": datetime.now().isoformat()
    #     # }
        
    #     # try:
    #     #     with self.vector_stores[department]:
    #     #         self.vector_stores[department].append({
    #     #             "text": text,
    #     #             "embedding": embedding,
    #     #             "metadata": metadata
    #     #         })
    #     #     print(f"[DEBUG] Added document '{filename}' to {department}")
    #     # except Exception as e:
    #     #     print(f"[ERROR] Failed to add document: {e}")
    #     print("[INFO] add_document disabled — uploads are stored only in Postgres/SQLite.")
    #     return []
    # --- Search ---
    def search_department(self, query: str, department: str, k: int = 5) -> List[SearchResult]:
        if department not in self.vector_stores:
            print(f"[ERROR] Department {department} not found in vector stores")
            return []

        print(f"[DEBUG] Searching in dept={department} for query: {query}")
        query_embedding = self.get_embedding(query)
        if not query_embedding:
            print("[ERROR] No embedding generated for query")
            return []

        try:
            ds = self.vector_stores[department]

            # Load embeddings, texts, and metadata as numpy arrays
            embeddings = np.stack(ds.embedding[:].numpy())
            texts = ds.text[:].numpy()
            metadatas = ds.metadata[:].numpy()

            # Compute cosine similarity (or dot product if normalized)
            sims = np.dot(embeddings, np.array(query_embedding))
            topk_idx = sims.argsort()[-k:][::-1]

            search_results = []
            for idx in topk_idx:
                # Decode text
                content = texts[idx].decode('utf-8') if isinstance(texts[idx], bytes) else str(texts[idx])
                
                # Decode metadata JSON
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

    def search_all_accessible(self, query: str, user_department: str, is_admin: bool, k: int = 5):
        departments = list(self.vector_stores.keys()) if is_admin else [user_department]
        all_results = []
        for dept in departments:
            all_results.extend(self.search_department(query, dept, k))
        return sorted(all_results, key=lambda x: x.relevance_score, reverse=True)[:k]

    # --- Generate AI response ---
    def generate_response(self, query: str, search_results: List[SearchResult]) -> str:
        if not search_results:
            return "Tôi không thể tìm thấy thông tin liên quan nào trong các tài liệu có sẵn."
        
        # Context from top 3 results
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
    
    # def upload_file(self, token: str, file_content: bytes, filename: str, text_content: str) -> Dict:
    #     """Upload file (only saves in Postgres + SQLite, not DeepLake)."""
    #     payload = self.security_manager.verify_token(token)
    #     if not payload:
    #         return {"success": False, "error": "Token không hợp lệ"}
        
    #     department = payload['department']
    #     username = payload['username']
        
    #     try:
    #         # Save file only
    #         file_id = self.file_manager.save_file(file_content, filename, department, username)
            
    #         # No DeepLake push
    #         return {
    #             "success": True,
    #             "file_id": file_id,
    #             "message": f"Tải file '{filename}' thành công vào phòng ban {department}"
    #         }
    #     except Exception as e:
    #         return {"success": False, "error": f"Lỗi: {str(e)}"}

    
    def upload_file(self, token: str, file_content: bytes, filename: str, text_content: Optional[str] = None) -> Dict:
        """Upload file (only saves in Postgres + SQLite, not DeepLake)."""
        payload = self.security_manager.verify_token(token)
        if not payload:
            return {"success": False, "error": "Token không hợp lệ"}
        
        department = payload['department']
        username = payload['username']
        
        try:
            # Save file only (text_content is ignored since we don't use it)
            file_id = self.file_manager.save_file(file_content, filename, department, username)
            
            # No DeepLake push - search uses pre-existing vectors
            return {
                "success": True,
                "file_id": file_id,
                "message": f"Tải file '{filename}' thành công vào phòng ban {department}"
            }
        except Exception as e:
            return {"success": False, "error": f"Lỗi: {str(e)}"}
    def search(self, token: str, query: str) -> Dict:
        payload = self.security_manager.verify_token(token)
        if not payload:
            return {"success": False, "error": "Token không hợp lệ"}
        
        department = payload['department']
        is_admin = payload['role'] == 'admin'
        print(f"[DEBUG] User {payload['username']} (role={payload['role']}) searching in dept={department}")
        
        try:
            results = self.rag_system.search_all_accessible(query, department, is_admin)
            print(f"[DEBUG] Search returned {len(results)} results for query '{query}'")
            
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
            print(f"[ERROR] Search failed: {e}")
            return {"success": False, "error": f"Lỗi tìm kiếm: {str(e)}"}

    
    def request_file_deletion(self, token: str, file_id: int) -> Dict:
        """Request file deletion"""
        payload = self.security_manager.verify_token(token)
        if not payload:
            return {"success": False, "error": "Token không hợp lệ"}
        
        success = self.file_manager.request_file_deletion(file_id, payload['username'])
        if success:
            return {"success": True, "message": "Yêu cầu xóa file đã được gửi để admin phê duyệt"}
        return {"success": False, "error": "Không thể gửi yêu cầu xóa file"}
    
    def approve_file_deletion(self, token: str, request_id: int) -> Dict:
        """Admin approves file deletion"""
        payload = self.security_manager.verify_token(token)
        if not payload or payload['role'] != 'admin':
            return {"success": False, "error": "Chỉ admin mới có quyền phê duyệt"}
        
        # Get file info before deletion
        conn = sqlite3.connect(self.security_manager.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT dr.file_id FROM delete_requests dr 
            WHERE dr.id = ? AND dr.status = 'pending'
        ''', (request_id,))
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return {"success": False, "error": "Yêu cầu không tồn tại hoặc đã được xử lý"}
        
        file_id = result[0]
        
        # Approve deletion
        success = self.file_manager.approve_deletion(request_id, payload['username'])
        if success:
            # Delete from ActiveLoop vector stores
            file_record = self.file_manager.get_file_record(file_id)
            if file_record and file_record.vector_ids:
                self.rag_system.delete_document_from_vectorstore(
                    file_record.vector_ids, 
                    file_record.department
                )
            return {"success": True, "message": "File đã được xóa thành công"}
        
        return {"success": False, "error": "Không thể phê duyệt xóa file"}

# Example usage
if __name__ == "__main__":
    # Initialize system
    rag_system = SecureRAGSystem()
    
    # Register users (in production, this would be done through admin interface)
    rag_system.security_manager.register_user("nhan_vien_ban_hang", "ban_hang", "matkhau123", UserRole.DEPARTMENT_USER)
    rag_system.security_manager.register_user("nhan_vien_marketing", "marketing", "matkhau456", UserRole.DEPARTMENT_USER)
    
    # Example login
    login_result = rag_system.login("nhan_vien_ban_hang", "matkhau123")
    if login_result["success"]:
        token = login_result["token"]
        print(f"Đăng nhập thành công. Token: {token[:20]}...")
        
        # Example search
        search_result = rag_system.search(token, "Mục tiêu bán hàng của chúng ta là gì?")
        print(f"Kết quả tìm kiếm: {search_result}")
    else:
        print(f"Đăng nhập thất bại: {login_result['error']}")