import os, io, csv, re
from datetime import date, timedelta
from functools import wraps
from urllib.parse import quote
import psycopg
from psycopg.rows import dict_row
from flask import Flask, request, redirect, url_for, session, flash, render_template, send_file, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-in-render")
DATABASE_URL = os.environ.get("DATABASE_URL", "")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "ChangeThisAdminPassword123!")
UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", "static/uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED = {"png", "jpg", "jpeg", "webp", "pdf"}

def db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is missing in Render Environment")
    url = DATABASE_URL.replace("postgres://", "postgresql://", 1) if DATABASE_URL.startswith("postgres://") else DATABASE_URL
    return psycopg.connect(url, row_factory=dict_row)

def init_db():
    with db() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS users (
          id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, phone TEXT DEFAULT '',
          area TEXT DEFAULT '', package TEXT DEFAULT '', fee DOUBLE PRECISION DEFAULT 0,
          expiry DATE, notes TEXT DEFAULT '', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        c.execute("""CREATE TABLE IF NOT EXISTS staff (
          id BIGSERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
          role TEXT NOT NULL DEFAULT 'worker', area TEXT DEFAULT '', active BOOLEAN DEFAULT TRUE,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        c.execute("""CREATE TABLE IF NOT EXISTS payments (
          id BIGSERIAL PRIMARY KEY, user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
          worker_username TEXT DEFAULT '', amount DOUBLE PRECISION NOT NULL DEFAULT 0,
          method TEXT NOT NULL DEFAULT 'Cash', paid_on DATE DEFAULT CURRENT_DATE,
          note TEXT DEFAULT '', proof_filename TEXT DEFAULT '', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        if not c.execute("SELECT id FROM staff WHERE username=%s", (ADMIN_USER,)).fetchone():
            c.execute("INSERT INTO staff(username,password_hash,role,area,active) VALUES(%s,%s,'admin','',TRUE)",
                      (ADMIN_USER, generate_password_hash(ADMIN_PASSWORD)))
init_db()

def who():
    if "username" not in session: return None
    with db() as c:
        return c.execute("SELECT id,username,role,area,active FROM staff WHERE username=%s", (session["username"],)).fetchone()

def logged(fn):
    @wraps(fn)
    def inner(*a, **kw):
        u = who()
        if not u or not u["active"]:
            session.clear(); return redirect(url_for("login"))
        return fn(*a, **kw)
    return inner

def admin(fn):
    @wraps(fn)
    def inner(*a, **kw):
        u = who()
        if not u or not u["active"]:
            session.clear(); return redirect(url_for("login"))
        if u["role"] != "admin": abort(403)
        return fn(*a, **kw)
    return inner

def expiry_value(v):
    v = (v or "").strip()
    if not v: return None
    try: return date.fromisoformat(v)
    except ValueError: return None

def allowed_file(name):
    return "." in name and name.rsplit(".", 1)[1].lower() in ALLOWED

@app.route("/")
@logged
def dashboard():
    u = who()
    with db() as c:
        if u["role"] == "admin":
            total = c.execute("SELECT COUNT(*) n FROM users").fetchone()["n"]
            due = c.execute("SELECT COUNT(*) n FROM users WHERE expiry IS NOT NULL AND expiry<=%s",
                            (date.today()+timedelta(days=2),)).fetchone()["n"]
            total_paid = c.execute("SELECT COALESCE(SUM(amount),0) n FROM payments").fetchone()["n"]
            rows = c.execute("""SELECT p.*,u.name,u.phone,u.area FROM payments p LEFT JOIN users u ON u.id=p.user_id
                                ORDER BY p.id DESC LIMIT 30""").fetchall()
            return render_template("dashboard.html", user=u, total=total, due=due, total_paid=total_paid, rows=rows)
        rows = c.execute("SELECT * FROM users WHERE area=%s AND expiry IS NOT NULL AND expiry<=%s ORDER BY expiry",
                         (u["area"] or "", date.today()+timedelta(days=2))).fetchall()
        total = c.execute("SELECT COUNT(*) n FROM users WHERE area=%s", (u["area"] or "",)).fetchone()["n"]
    return render_template("worker_dashboard.html", user=u, total=total, due=len(rows), users=rows)

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username=request.form.get("username","").strip(); password=request.form.get("password","")
        with db() as c: row=c.execute("SELECT * FROM staff WHERE username=%s",(username,)).fetchone()
        if row and row["active"] and check_password_hash(row["password_hash"],password):
            session.clear(); session["username"]=username; return redirect("/")
        flash("Username ya password ghalat hai.", "error")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear(); return redirect("/login")

@app.route("/customers")
@logged
def customers():
    u=who(); q=request.args.get("q","").strip(); area=request.args.get("area","").strip()
    with db() as c:
        areas=c.execute("SELECT DISTINCT area FROM users WHERE area<>'' ORDER BY area").fetchall()
        sql="SELECT * FROM users WHERE (name ILIKE %s OR phone ILIKE %s OR area ILIKE %s)"
        args=[f"%{q}%",f"%{q}%",f"%{q}%"]
        if u["role"]!="admin": sql+=" AND area=%s"; args.append(u["area"] or "")
        elif area: sql+=" AND area=%s"; args.append(area)
        rows=c.execute(sql+" ORDER BY id DESC LIMIT 2000",args).fetchall()
    return render_template("customers.html",user=u,users=rows,q=q,area=area,areas=areas)

@app.route("/customers/add", methods=["POST"])
@logged
def add_customer():
    u=who(); f=request.form; name=f.get("name","").strip()
    if not name: flash("Naam zaroori hai.","error"); return redirect("/customers")
    area=f.get("area","").strip() if u["role"]=="admin" else (u["area"] or "")
    with db() as c:
        c.execute("""INSERT INTO users(name,phone,area,package,fee,expiry,notes) VALUES(%s,%s,%s,%s,%s,%s,%s)""",
          (name,f.get("phone","").strip(),area,f.get("package","").strip(),float(f.get("fee") or 0),
           expiry_value(f.get("expiry")),f.get("notes","").strip()))
    flash("Customer save ho gaya.","success"); return redirect("/customers")

@app.route("/customers/import", methods=["POST"])
@admin
def import_customers():
    file=request.files.get("file")
    if not file or not file.filename: flash("CSV file select karein.","error"); return redirect("/customers")
    try:
        reader=csv.DictReader(io.StringIO(file.read().decode("utf-8-sig")))
        if not reader.fieldnames or "name" not in [x.strip().lower() for x in reader.fieldnames]:
            raise ValueError("CSV mein name column zaroori hai.")
        count=0
        with db() as c:
            for row in reader:
                d={str(k).strip().lower():(v or "").strip() for k,v in row.items() if k}
                if not d.get("name"): continue
                if count>=2000: break
                c.execute("""INSERT INTO users(name,phone,area,package,fee,expiry,notes) VALUES(%s,%s,%s,%s,%s,%s,%s)""",
                  (d["name"],d.get("phone",""),d.get("area",""),d.get("package",""),float(d.get("fee") or 0),
                   expiry_value(d.get("expiry")),d.get("notes","")))
                count+=1
        flash(f"{count} customers import ho gaye.","success")
    except Exception as e: flash("CSV import error: "+str(e),"error")
    return redirect("/customers")

@app.route("/customers/template")
@logged
def template_csv():
    if who()["role"]!="admin": abort(403)
    b=io.BytesIO(b"name,phone,area,package,fee,expiry,notes\\nAli,03001234567,Area A,50 MB,1500,2026-12-01,\\n")
    return send_file(b,as_attachment=True,download_name="rj-customers-template.csv",mimetype="text/csv")

@app.route("/export")
@logged
def export():
    u=who()
    with db() as c:
        rows=c.execute("SELECT * FROM users ORDER BY id" if u["role"]=="admin" else
                       "SELECT * FROM users WHERE area=%s ORDER BY id",( ) if u["role"]=="admin" else (u["area"] or "",)).fetchall()
    out=io.StringIO(); w=csv.writer(out); w.writerow(["id","name","phone","area","package","fee","expiry","notes","created_at"])
    for r in rows: w.writerow([r[k] for k in ["id","name","phone","area","package","fee","expiry","notes","created_at"]])
    b=io.BytesIO(out.getvalue().encode("utf-8-sig")); b.seek(0)
    return send_file(b,as_attachment=True,download_name="rj-customers-backup.csv",mimetype="text/csv")

@app.route("/payments", methods=["GET","POST"])
@logged
def payments():
    u=who()
    if request.method=="POST":
        f=request.form; uid=int(f.get("user_id") or 0); amount=float(f.get("amount") or 0)
        method=f.get("method","Cash"); note=f.get("note","").strip(); proof=""
        upload=request.files.get("proof")
        if method=="Online":
            if not upload or not upload.filename: flash("Online payment ke liye screenshot/PDF attach karein.","error"); return redirect("/payments")
            if not allowed_file(upload.filename): flash("Proof PNG/JPG/WEBP/PDF hona chahiye.","error"); return redirect("/payments")
            proof=secure_filename(f"{date.today().isoformat()}_{session['username']}_{upload.filename}")
            upload.save(os.path.join(UPLOAD_FOLDER,proof))
        with db() as c:
            customer=c.execute("SELECT * FROM users WHERE id=%s",(uid,)).fetchone()
            if not customer: flash("Customer nahi mila.","error"); return redirect("/payments")
            if u["role"]!="admin" and customer["area"]!=(u["area"] or ""): abort(403)
            if amount<=0: flash("Amount zero se zyada hona chahiye.","error"); return redirect("/payments")
            c.execute("""INSERT INTO payments(user_id,worker_username,amount,method,paid_on,note,proof_filename)
                         VALUES(%s,%s,%s,%s,%s,%s,%s)""",
                      (uid,session["username"],amount,method,expiry_value(f.get("paid_on")) or date.today(),note,proof))
        flash("Payment save ho gayi.","success"); return redirect("/payments")
    with db() as c:
        if u["role"]=="admin":
            users=c.execute("SELECT id,name,phone,area FROM users ORDER BY name").fetchall()
            rows=c.execute("""SELECT p.*,u.name,u.phone,u.area FROM payments p LEFT JOIN users u ON u.id=p.user_id
                              ORDER BY p.id DESC LIMIT 500""").fetchall()
        else:
            users=c.execute("SELECT id,name,phone,area FROM users WHERE area=%s ORDER BY name",(u["area"] or "",)).fetchall()
            rows=c.execute("""SELECT p.*,u.name,u.phone,u.area FROM payments p LEFT JOIN users u ON u.id=p.user_id
                              WHERE p.worker_username=%s ORDER BY p.id DESC LIMIT 500""",(session["username"],)).fetchall()
    return render_template("payments.html",user=u,users=users,rows=rows,today=date.today().isoformat())

@app.route("/proof/<int:pid>")
@logged
def proof(pid):
    u=who()
    with db() as c:
        p=c.execute("SELECT p.proof_filename,u.area FROM payments p LEFT JOIN users u ON u.id=p.user_id WHERE p.id=%s",(pid,)).fetchone()
    if not p or not p["proof_filename"]: abort(404)
    if u["role"]!="admin" and p["area"]!=(u["area"] or ""): abort(403)
    return redirect(url_for("static",filename="uploads/"+p["proof_filename"]))

@app.route("/workers",methods=["GET","POST"])
@admin
def workers():
    if request.method=="POST":
        f=request.form; username=f.get("username","").strip(); password=f.get("password",""); area=f.get("area","").strip()
        if not username or len(password)<8 or not area:
            flash("Username, area aur 8+ character password zaroori hain.","error"); return redirect("/workers")
        try:
            with db() as c: c.execute("INSERT INTO staff(username,password_hash,role,area,active) VALUES(%s,%s,'worker',%s,TRUE)",
                                      (username,generate_password_hash(password),area))
            flash("Worker account ban gaya.","success")
        except psycopg.errors.UniqueViolation: flash("Yeh username pehle se mojood hai.","error")
        return redirect("/workers")
    with db() as c:
        staff=c.execute("SELECT id,username,role,area,active FROM staff ORDER BY role,username").fetchall()
        areas=c.execute("SELECT DISTINCT area FROM users WHERE area<>'' ORDER BY area").fetchall()
    return render_template("workers.html",user=who(),staff=staff,areas=areas)

@app.route("/workers/<int:wid>/toggle",methods=["POST"])
@admin
def toggle_worker(wid):
    with db() as c: c.execute("UPDATE staff SET active=NOT active WHERE id=%s AND role='worker'",(wid,))
    flash("Worker status update ho gaya.","success"); return redirect("/workers")

@app.route("/whatsapp/<int:uid>")
@logged
def whatsapp(uid):
    u=who()
    with db() as c: customer=c.execute("SELECT * FROM users WHERE id=%s",(uid,)).fetchone()
    if not customer: abort(404)
    if u["role"]!="admin" and customer["area"]!=(u["area"] or ""): abort(403)
    phone=re.sub(r"\D","",customer["phone"] or "")
    if phone.startswith("0"): phone="92"+phone[1:]
    if not phone: flash("Customer ka phone number nahi hai.","error"); return redirect("/customers")
    msg=f"Assalam-o-Alaikum {customer['name']} sahib, RJ Networks ki taraf se fee reminder. Package: {customer['package']}, fee Rs. {customer['fee']}, expiry: {customer['expiry'] or 'date available nahi'}. Barah-e-karam fee jama karwa dein. Shukriya."
    return redirect("https://wa.me/"+phone+"?text="+quote(msg))

@app.route("/health")
def health(): return {"status":"ok"}

@app.errorhandler(403)
def forbidden(_): return "Aap ko is page ki ijazat nahi hai.",403

if __name__=="__main__": app.run(host="0.0.0.0",port=int(os.environ.get("PORT",5000)))
