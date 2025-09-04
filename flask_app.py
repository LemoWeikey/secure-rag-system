# app.py - Production Version
from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from werkzeug.utils import secure_filename
import os
from io import BytesIO
from flask import Flask, request, jsonify, send_file
from io import BytesIO
# Import our secure RAG system - make sure this file is named secure_rag_system.py
from secure_rag_system import SecureRAGSystem, UserRole
from dotenv import load_dotenv
import sqlite3

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "super-secret-key")  # Required for sessions
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Initialize the RAG system
rag_system = SecureRAGSystem()

# -------------------- LIST FILES --------------------
@app.route("/api/files", methods=["GET"])
def list_files():
    """List all files available for the authenticated user (filtered by department unless admin)."""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    payload = rag_system.security_manager.verify_token(token)
    if not payload:
        return jsonify({"success": False, "error": "Token không hợp lệ"}), 401

    department = payload["department"]
    is_admin = payload["role"] == "admin"

    conn = sqlite3.connect(rag_system.security_manager.db_path)
    cursor = conn.cursor()

    if is_admin:
        cursor.execute("SELECT id, filename, department, uploaded_by, upload_date, status FROM files WHERE status = 'active'")
    else:
        cursor.execute("SELECT id, filename, department, uploaded_by, upload_date, status FROM files WHERE department = ? AND status = 'active'", (department,))

    rows = cursor.fetchall()
    conn.close()

    files = []
    for r in rows:
        files.append({
            "id": r[0],
            "filename": r[1],
            "department": r[2],
            "uploaded_by": r[3],
            "upload_date": r[4],
            "status": r[5]
        })

    return jsonify({"success": True, "files": files})


# -------------------- DOWNLOAD FILE --------------------
@app.route("/api/download/<int:file_id>", methods=["GET"])
def download_file(file_id):
    """Download a file by ID if the user has access."""
    # Try header first
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:  
        # Fallback: try query param ?token=...
        token = request.args.get("token", "")

    payload = rag_system.security_manager.verify_token(token)
    if not payload:
        return jsonify({"success": False, "error": "Token không hợp lệ"}), 401

    department = payload["department"]
    is_admin = payload["role"] == "admin"

    # Get file metadata from SQLite
    file_record = rag_system.file_manager.get_file_record(file_id)
    if not file_record:
        return jsonify({"success": False, "error": "File không tồn tại"}), 404

    # Check access
    if not is_admin and file_record.department != department:
        return jsonify({"success": False, "error": "Bạn không có quyền tải file này"}), 403

    # Fetch file bytes (from Postgres or local storage)
    file_bytes = rag_system.file_manager.fetch_file_bytes_from_postgres(file_record)
    if not file_bytes:
        return jsonify({"success": False, "error": "Không tìm thấy nội dung file"}), 500

    # Send file as attachment
    return send_file(
        BytesIO(file_bytes),
        as_attachment=True,
        download_name=file_record.filename,
        mimetype="application/octet-stream"
    )

# Routes
@app.route("/health")
def healthcheck():
    return "OK", 200

@app.route("/")
def login_page():
    return render_template("login.html")

@app.route('/dashboard')
def dashboard():
    return render_template("dashboard.html")

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({"success": False, "error": "Tên đăng nhập và mật khẩu là bắt buộc"}), 400
    
    result = rag_system.login(username, password)
    
    if result["success"]:
        # Save token into session for web-based users
        session["token"] = result.get("token")
        return jsonify(result), 200
    else:
        return jsonify(result), 401

@app.route('/api/upload', methods=['POST'])
def upload_file():
    # Get token from Authorization header or session
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
    else:
        token = session.get("token")
    
    if not token:
        return jsonify({"success": False, "error": "Token xác thực là bắt buộc"}), 401
    
    if 'file' not in request.files:
        return jsonify({"success": False, "error": "Chưa có file được cung cấp"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"success": False, "error": "Chưa chọn file"}), 400
    
    try:
        file_content = file.read()
        filename = secure_filename(file.filename)
        
        # Store file directly without text extraction
        result = rag_system.upload_file(token, file_content, filename, text_content=None)
        
        return jsonify(result), 200 if result["success"] else 400
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/search', methods=['POST'])
def search_documents():
    # Get token from Authorization header or session
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
    else:
        token = session.get("token")
    
    if not token:
        return jsonify({"success": False, "error": "Token xác thực là bắt buộc"}), 401
    
    data = request.get_json()
    query = data.get("query", "").strip()
    
    if not query:
        return jsonify({"success": False, "error": "Câu hỏi không được để trống"}), 400

    result = rag_system.search(token, query)
    return jsonify(result), 200 if result["success"] else 400

@app.route('/api/delete-request', methods=['POST'])
def request_delete():
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
    else:
        token = session.get("token")
    
    if not token:
        return jsonify({"success": False, "error": "Token xác thực là bắt buộc"}), 401
    
    data = request.get_json()
    file_id = data.get('file_id')
    
    if not file_id:
        return jsonify({"success": False, "error": "ID file là bắt buộc"}), 400
    
    result = rag_system.request_file_deletion(token, file_id)
    return jsonify(result), 200 if result["success"] else 400

@app.route('/api/admin/delete-requests', methods=['GET'])
def get_delete_requests():
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
    else:
        token = session.get("token")
    
    if not token:
        return jsonify({"success": False, "error": "Token xác thực là bắt buộc"}), 401
    
    payload = rag_system.security_manager.verify_token(token)
    if not payload or payload.get('role') != 'admin':
        return jsonify({"success": False, "error": "Cần quyền admin"}), 403
    
    try:
        import sqlite3
        conn = sqlite3.connect(rag_system.security_manager.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT dr.id, dr.file_id, dr.requested_by, dr.request_date, f.filename
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
                "filename": row[4]
            })
        
        conn.close()
        
        return jsonify({"success": True, "requests": requests}), 200
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/admin/approve-delete', methods=['POST'])
def approve_delete():
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
    else:
        token = session.get("token")
    
    if not token:
        return jsonify({"success": False, "error": "Token xác thực là bắt buộc"}), 401
    
    data = request.get_json()
    request_id = data.get('request_id')
    
    if not request_id:
        return jsonify({"success": False, "error": "ID yêu cầu là bắt buộc"}), 400
    
    result = rag_system.approve_file_deletion(token, request_id)
    return jsonify(result), 200 if result["success"] else 400

@app.route('/api/admin/create-user', methods=['POST'])
def create_department_user():
    # Verify admin token
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    payload = rag_system.security_manager.verify_token(token)
    
    if not payload or payload.get('role') != 'admin':
        return jsonify({"success": False, "error": "Admin access required"}), 403
    
    data = request.get_json()
    try:
        rag_system.security_manager.register_user(
            data['username'],
            data['department'], 
            data['password'],
            UserRole.DEPARTMENT_USER
        )
        return jsonify({"success": True, "message": "User created successfully"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

# Create admin user setup (run once)
def setup_admin_user():
    """Setup initial admin user - run once on first deployment"""
    try:
        admin_username = os.getenv("ADMIN_USERNAME")
        admin_password = os.getenv("ADMIN_PASSWORD")
        
        if not admin_username or not admin_password:
            print("⚠️  ADMIN_USERNAME and ADMIN_PASSWORD must be set in environment variables")
            return False
        
        # Check if admin already exists
        conn = sqlite3.connect(rag_system.security_manager.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE username = ?", (admin_username,))
        if cursor.fetchone():
            print(f"ℹ️  Admin user '{admin_username}' already exists")
            conn.close()
            return True
        conn.close()
        
        # Create admin user
        success = rag_system.security_manager.register_user(
            admin_username, 
            "admin_department", 
            admin_password, 
            UserRole.ADMIN
        )
        
        if success:
            print(f"✅ Admin user created: {admin_username}")
            print("⚠️  IMPORTANT: Change admin password after first login!")
            return True
        else:
            print(f"❌ Failed to create admin user")
            return False
        
    except Exception as e:
        print(f"❌ Admin user setup failed: {e}")
        return False

if __name__ == '__main__':
    # Create necessary directories
    os.makedirs("files", exist_ok=True)
    
    # Setup admin user if requested
    if os.getenv("SETUP_ADMIN", "false").lower() == "true":
        setup_admin_user()
    
    # Railway deployment settings
    port = int(os.getenv("PORT", 8080))
    host = os.getenv("HOST", "0.0.0.0")
    debug = os.getenv("DEBUG", "false").lower() == "true"
    
    print("🚀 Starting SecureRAG on Railway...")
    print(f"🌐 Server: {host}:{port}")
    print("📧 Contact admin for account access")
    
    # Display database connection status
    if os.getenv("DATABASE_URL"):
        print("📊 Database: PostgreSQL configured")
    else:
        print("📊 Database: SQLite fallback mode")
    
    app.run(host=host, port=port, debug=debug)