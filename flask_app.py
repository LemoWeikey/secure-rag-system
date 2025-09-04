# app.py - Enhanced Production Version with Department Hierarchy
from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from werkzeug.utils import secure_filename
import os
from io import BytesIO
from flask import Flask, request, jsonify, send_file
from io import BytesIO
from secure_rag_system import SecureRAGSystem, UserRole
from dotenv import load_dotenv
import sqlite3

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "super-secret-key")
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Initialize the RAG system
rag_system = SecureRAGSystem()

# ===================== AUTHENTICATION ROUTES =====================

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
        session["token"] = result.get("token")
        return jsonify(result), 200
    else:
        return jsonify(result), 401

# ===================== USER MANAGEMENT ROUTES =====================

@app.route('/api/admin/create-department-head', methods=['POST'])
def create_department_head():
    """Admin creates department head"""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        token = session.get("token")
    
    if not token:
        return jsonify({"success": False, "error": "Token xác thực là bắt buộc"}), 401
    
    data = request.get_json()
    username = data.get('username')
    department = data.get('department')
    password = data.get('password')
    
    if not all([username, department, password]):
        return jsonify({"success": False, "error": "Thiếu thông tin bắt buộc"}), 400
    
    result = rag_system.create_department_head(token, username, department, password)
    return jsonify(result), 200 if result["success"] else 400

@app.route('/api/create-employee', methods=['POST'])
def create_employee():
    """Department head or admin creates employee"""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        token = session.get("token")
    
    if not token:
        return jsonify({"success": False, "error": "Token xác thực là bắt buộc"}), 401
    
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not all([username, password]):
        return jsonify({"success": False, "error": "Thiếu tên đăng nhập hoặc mật khẩu"}), 400
    
    result = rag_system.create_employee(token, username, password)
    return jsonify(result), 200 if result["success"] else 400

@app.route('/api/departments', methods=['GET'])
def get_departments():
    """Get all departments (admin only)"""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        token = session.get("token")
    
    if not token:
        return jsonify({"success": False, "error": "Token xác thực là bắt buộc"}), 401
    
    result = rag_system.get_departments(token)
    return jsonify(result), 200 if result["success"] else 403

@app.route('/api/department-users', methods=['GET'])
def get_department_users():
    """Get users in department"""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        token = session.get("token")
    
    if not token:
        return jsonify({"success": False, "error": "Token xác thực là bắt buộc"}), 401
    
    department = request.args.get('department')
    result = rag_system.get_department_users(token, department)
    return jsonify(result), 200 if result["success"] else 403

# ===================== FILE MANAGEMENT ROUTES =====================

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

@app.route("/api/download/<int:file_id>", methods=["GET"])
def download_file(file_id):
    """Download a file by ID if the user has access."""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:  
        token = request.args.get("token", "")

    payload = rag_system.security_manager.verify_token(token)
    if not payload:
        return jsonify({"success": False, "error": "Token không hợp lệ"}), 401

    department = payload["department"]
    is_admin = payload["role"] == "admin"

    file_record = rag_system.file_manager.get_file_record(file_id)
    if not file_record:
        return jsonify({"success": False, "error": "File không tồn tại"}), 404

    # Check access - admin or same department
    if not is_admin and file_record.department != department:
        return jsonify({"success": False, "error": "Bạn không có quyền tải file này"}), 403

    file_bytes = rag_system.file_manager.fetch_file_bytes_from_postgres(file_record)
    if not file_bytes:
        return jsonify({"success": False, "error": "Không tìm thấy nội dung file"}), 500

    return send_file(
        BytesIO(file_bytes),
        as_attachment=True,
        download_name=file_record.filename,
        mimetype="application/octet-stream"
    )

@app.route('/api/upload', methods=['POST'])
def upload_file():
    """Upload file"""
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
        
        result = rag_system.upload_file(token, file_content, filename, text_content=None)
        return jsonify(result), 200 if result["success"] else 400
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# ===================== SEARCH ROUTES =====================

@app.route('/api/search', methods=['POST'])
def search_documents():
    """Search documents with role-based access"""
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

# ===================== FILE DELETION ROUTES =====================

@app.route('/api/delete-request', methods=['POST'])
def request_delete():
    """Request file deletion with enhanced role-based logic"""
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

@app.route('/api/delete-requests', methods=['GET'])
def get_delete_requests():
    """Get pending deletion requests based on user role"""
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
    else:
        token = session.get("token")
    
    if not token:
        return jsonify({"success": False, "error": "Token xác thực là bắt buộc"}), 401
    
    result = rag_system.get_pending_deletions(token)
    return jsonify(result), 200 if result["success"] else 403

@app.route('/api/approve-delete', methods=['POST'])
def approve_delete():
    """Approve file deletion (admin or department head)"""
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

# ===================== ADMIN LEGACY ROUTES (for backward compatibility) =====================

@app.route('/api/admin/create-user', methods=['POST'])
def create_department_user():
    """Legacy route - now creates employee"""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    payload = rag_system.security_manager.verify_token(token)
    
    if not payload or payload.get('role') not in ['admin', 'department_head']:
        return jsonify({"success": False, "error": "Admin or Department Head access required"}), 403
    
    data = request.get_json()
    try:
        # Create employee in the same department as the creator
        result = rag_system.create_employee(token, data['username'], data['password'])
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

@app.route('/api/admin/delete-requests', methods=['GET'])
def get_admin_delete_requests():
    """Legacy admin route"""
    return get_delete_requests()

@app.route('/api/admin/approve-delete', methods=['POST'])
def admin_approve_delete():
    """Legacy admin route"""
    return approve_delete()

# ===================== UTILITY ROUTES =====================

@app.route('/api/user-info', methods=['GET'])
def get_user_info():
    """Get current user information"""
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
    else:
        token = session.get("token")
    
    if not token:
        return jsonify({"success": False, "error": "Token xác thực là bắt buộc"}), 401
    
    payload = rag_system.security_manager.verify_token(token)
    if not payload:
        return jsonify({"success": False, "error": "Token không hợp lệ"}), 401
    
    return jsonify({
        "success": True,
        "user": {
            "username": payload['username'],
            "department": payload['department'],
            "role": payload['role']
        }
    })

# ===================== SETUP FUNCTIONS =====================

def setup_initial_accounts():
    """Setup initial admin, department heads, and employees"""
    try:
        admin_username = os.getenv("ADMIN_USERNAME")
        admin_password = os.getenv("ADMIN_PASSWORD")
        
        if not admin_username or not admin_password:
            print("⚠️  ADMIN_USERNAME and ADMIN_PASSWORD must be set")
            return False
        
        # Check if admin exists
        conn = sqlite3.connect(rag_system.security_manager.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE username = ?", (admin_username,))
        admin_exists = cursor.fetchone()
        conn.close()
        
        # Create admin if doesn't exist
        if not admin_exists:
            success = rag_system.security_manager.register_user(
                admin_username, "admin_department", admin_password, UserRole.ADMIN
            )
            if success:
                print(f"✅ Admin user created: {admin_username}")
            else:
                print("❌ Failed to create admin user")
                return False
        else:
            print(f"ℹ️  Admin user '{admin_username}' already exists")
        
        # Login as admin to create department heads and employees
        admin_login = rag_system.login(admin_username, admin_password)
        if not admin_login["success"]:
            print("❌ Failed to login as admin")
            return False
            
        admin_token = admin_login["token"]
        
        # Create department heads
        dept_heads = [
            ("MARKETING_HEAD_USERNAME", "MARKETING_HEAD_PASSWORD", "marketing"),
            ("SALES_HEAD_USERNAME", "SALES_HEAD_PASSWORD", "sales")
        ]
        
        dept_head_tokens = {}
        
        for username_env, password_env, department in dept_heads:
            username = os.getenv(username_env)
            password = os.getenv(password_env)
            
            if username and password:
                result = rag_system.create_department_head(admin_token, username, department, password)
                if result["success"]:
                    print(f"✅ {department.title()} head created: {username}")
                    # Login as department head to get token
                    head_login = rag_system.login(username, password)
                    if head_login["success"]:
                        dept_head_tokens[department] = head_login["token"]
                else:
                    print(f"ℹ️  {department.title()} head creation: {result.get('error', 'Unknown error')}")
        
        # Create employees if SETUP_EMPLOYEES is true
        if os.getenv("SETUP_EMPLOYEES", "false").lower() == "true":
            print("🔧 Setting up employee accounts...")
            
            # Marketing employees
            marketing_employees = []
            for i in range(1, 10):  # Check for up to 9 employees
                username = os.getenv(f"MARKETING_EMP{i}_USERNAME")
                password = os.getenv(f"MARKETING_EMP{i}_PASSWORD")
                fullname = os.getenv(f"MARKETING_EMP{i}_FULLNAME", "")
                
                if username and password:
                    marketing_employees.append((username, password, fullname))
                else:
                    break  # Stop when no more employees found
            
            # Sales employees
            sales_employees = []
            for i in range(1, 10):  # Check for up to 9 employees
                username = os.getenv(f"SALES_EMP{i}_USERNAME")
                password = os.getenv(f"SALES_EMP{i}_PASSWORD")
                fullname = os.getenv(f"SALES_EMP{i}_FULLNAME", "")
                
                if username and password:
                    sales_employees.append((username, password, fullname))
                else:
                    break  # Stop when no more employees found
            
            # Create marketing employees
            if marketing_employees and "marketing" in dept_head_tokens:
                marketing_token = dept_head_tokens["marketing"]
                for username, password, fullname in marketing_employees:
                    result = rag_system.create_employee_with_details(marketing_token, username, password, fullname)
                    if result["success"]:
                        print(f"✅ Marketing employee created: {username} ({fullname})")
                    else:
                        print(f"⚠️  Marketing employee creation failed: {username} - {result.get('error')}")
            
            # Create sales employees
            if sales_employees and "sales" in dept_head_tokens:
                sales_token = dept_head_tokens["sales"]
                for username, password, fullname in sales_employees:
                    result = rag_system.create_employee_with_details(sales_token, username, password, fullname)
                    if result["success"]:
                        print(f"✅ Sales employee created: {username} ({fullname})")
                    else:
                        print(f"⚠️  Sales employee creation failed: {username} - {result.get('error')}")
            
            print(f"📊 Total marketing employees: {len(marketing_employees)}")
            print(f"📊 Total sales employees: {len(sales_employees)}")
        
        return True
        
    except Exception as e:
        print(f"❌ Initial setup failed: {e}")
        return False


# Also update the main section at the bottom of app.py:

if __name__ == '__main__':
    # Create necessary directories
    os.makedirs("files", exist_ok=True)
    
    # Setup initial accounts if requested
    if os.getenv("SETUP_ADMIN", "false").lower() == "true":
        print("🔧 Setting up initial accounts...")
        setup_success = setup_initial_accounts()
        if setup_success:
            print("✅ Initial setup completed successfully!")
        else:
            print("❌ Initial setup failed!")
    
    # Railway deployment settings
    port = int(os.getenv("PORT", 8080))
    host = os.getenv("HOST", "0.0.0.0")
    debug = os.getenv("DEBUG", "false").lower() == "true"
    
    print("🚀 Starting Enhanced SecureRAG with Department Hierarchy...")
    print(f"🌐 Server: {host}:{port}")
    print("📊 Role System: Admin → Department Heads → Employees")
    print("🏢 Departments: Marketing, Sales")
    
    # Display database connection status
    if os.getenv("DATABASE_URL"):
        print("📊 Database: PostgreSQL configured")
    else:
        print("📊 Database: SQLite fallback mode")
    
    # Show setup status
    if os.getenv("SETUP_ADMIN", "false").lower() == "true":
        print("🔧 Auto-setup: ENABLED")
    else:
        print("ℹ️  Auto-setup: DISABLED (set SETUP_ADMIN=true to enable)")
        
    if os.getenv("SETUP_EMPLOYEES", "false").lower() == "true":
        print("👥 Employee auto-creation: ENABLED")
    else:
        print("👥 Employee auto-creation: DISABLED")
    
    app.run(host=host, port=port, debug=debug)