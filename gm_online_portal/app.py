import os, sqlite3, hashlib, secrets, calendar, io
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, abort
from werkzeug.security import generate_password_hash, check_password_hash

APP_NAME = 'GM International College Management System'
BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE, 'portal.db')
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'change-this-secret-key')

MONTHS = [calendar.month_name[i] for i in range(1,13)]
BUS_LIST = [f'BUS {i}' for i in range(1,16)]
EXPENSES = ['Driver Salary','Fuel','Bus Maintenance','Bus Parking','Other']

def hp(s): return hashlib.sha256(s.encode()).hexdigest()

def db():
    c=sqlite3.connect(DB_PATH)
    c.row_factory=sqlite3.Row
    c.execute('PRAGMA foreign_keys=ON')
    return c

def setup():
    c=db()
    c.executescript('''
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'Staff', active INTEGER DEFAULT 1, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS tenants(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, active INTEGER DEFAULT 1, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS memberships(id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL, username TEXT NOT NULL, password_hash TEXT NOT NULL, role TEXT DEFAULT 'Admin', active INTEGER DEFAULT 1, created_at TEXT DEFAULT CURRENT_TIMESTAMP, UNIQUE(tenant_id,username), FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE);
    CREATE TABLE IF NOT EXISTS students(id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL, student_name TEXT NOT NULL, father_name TEXT, address TEXT, class_name TEXT, contact TEXT, dob TEXT, bus_no INTEGER, family_id TEXT, monthly_fee REAL DEFAULT 0, join_date TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE);
    CREATE TABLE IF NOT EXISTS payments(id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL, student_id INTEGER NOT NULL, month INTEGER NOT NULL, year INTEGER NOT NULL, amount REAL NOT NULL, payment_date TEXT NOT NULL, receipt_no TEXT UNIQUE, notes TEXT, created_by TEXT, group_receipt_no TEXT, UNIQUE(student_id,month,year), FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE, FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE);
    CREATE TABLE IF NOT EXISTS expenses(id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL, expense_date TEXT NOT NULL, month INTEGER NOT NULL, year INTEGER NOT NULL, category TEXT NOT NULL, description TEXT, amount REAL NOT NULL, notes TEXT, created_by TEXT, FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE);
    CREATE TABLE IF NOT EXISTS staff(id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL, staff_name TEXT NOT NULL, designation TEXT, contact TEXT, visa_expiry TEXT, insurance_expiry TEXT, notes TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE);
    CREATE TABLE IF NOT EXISTS drivers_vehicles(id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL, vehicle_number TEXT NOT NULL, driver_name TEXT NOT NULL, vehicle_insurance_expiry TEXT, vehicle_license_expiry TEXT, driver_license_expiry TEXT, driver_visa_expiry TEXT, notes TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE);
    ''')
    if c.execute('SELECT COUNT(*) FROM users').fetchone()[0]==0:
        c.execute('INSERT INTO users(username,password_hash,role,active) VALUES(?,?,?,1)',('superadmin',generate_password_hash('admin123'),'SuperAdmin'))
    c.commit(); c.close()

setup()

def login_required(f):
    @wraps(f)
    def w(*a,**kw):
        if 'user_id' not in session: return redirect(url_for('login'))
        return f(*a,**kw)
    return w

def super_required(f):
    @wraps(f)
    def w(*a,**kw):
        if session.get('role')!='SuperAdmin': abort(403)
        return f(*a,**kw)
    return w

def tenant_required(f):
    @wraps(f)
    def w(*a,**kw):
        if not session.get('tenant_id'): return redirect(url_for('superadmin'))
        return f(*a,**kw)
    return w

def tid(): return session['tenant_id']

def tenant_rows(sql,args=()):
    c=db(); rows=c.execute(sql,args).fetchall(); c.close(); return rows

def make_receipt(): return 'GM-'+datetime.now().strftime('%Y%m%d%H%M%S')+'-'+secrets.token_hex(2).upper()

@app.context_processor
def ctx():
    return {'app_name':APP_NAME,'months':MONTHS,'bus_list':BUS_LIST,'year':datetime.now().year,'session':session,'enumerate':enumerate,'max':max}

@app.route('/')
def index():
    if 'user_id' not in session: return redirect(url_for('login'))
    return redirect(url_for('superadmin' if session.get('role')=='SuperAdmin' else 'dashboard'))

@app.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        u=request.form.get('username','').strip(); p=request.form.get('password','')
        c=db(); row=c.execute('SELECT * FROM users WHERE username=?',(u,)).fetchone()
        if row and row['active'] and check_password_hash(row['password_hash'],p):
            session.clear(); session.update(user_id=row['id'],username=row['username'],role=row['role'])
            if row['role']=='SuperAdmin': return redirect(url_for('superadmin'))
        else:
            # customer/tenant login
            m=c.execute('SELECT m.*,t.name tenant_name,t.active tenant_active FROM memberships m JOIN tenants t ON t.id=m.tenant_id WHERE m.username=?',(u,)).fetchone()
            if m and m['active'] and m['tenant_active'] and check_password_hash(m['password_hash'],p):
                session.clear(); session.update(user_id=m['id'],username=m['username'],role=m['role'],tenant_id=m['tenant_id'],tenant_name=m['tenant_name'])
                return redirect(url_for('dashboard'))
        flash('Invalid username/password or account is inactive.','danger')
    return render_template('login.html')

@app.route('/logout')
def logout(): session.clear(); return redirect(url_for('login'))

@app.route('/superadmin')
@login_required
@super_required
def superadmin():
    c=db(); tenants=c.execute('SELECT t.*,COUNT(m.id) admins FROM tenants t LEFT JOIN memberships m ON m.tenant_id=t.id GROUP BY t.id ORDER BY t.id DESC').fetchall(); c.close()
    return render_template('superadmin.html',tenants=tenants)

@app.route('/superadmin/tenant',methods=['POST'])
@login_required
@super_required
def create_tenant():
    name=request.form.get('name','').strip(); username=request.form.get('username','').strip(); password=request.form.get('password','')
    if not name or not username or not password: flash('College/customer name, username and password are required.','danger'); return redirect(url_for('superadmin'))
    c=db()
    try:
        cur=c.execute('INSERT INTO tenants(name,active) VALUES(?,1)',(name,)); tenant=cur.lastrowid
        c.execute('INSERT INTO memberships(tenant_id,username,password_hash,role,active) VALUES(?,?,?,?,1)',(tenant,username,generate_password_hash(password),'Admin'))
        c.commit(); flash('Customer portal created successfully.','success')
    except sqlite3.IntegrityError as e: c.rollback(); flash('Username or customer name already exists.','danger')
    finally: c.close()
    return redirect(url_for('superadmin'))

@app.route('/superadmin/toggle/<int:tenant_id>',methods=['POST'])
@login_required
@super_required
def toggle_tenant(tenant_id):
    c=db(); c.execute('UPDATE tenants SET active=1-active WHERE id=?',(tenant_id,)); c.commit(); c.close(); return redirect(url_for('superadmin'))

@app.route('/superadmin/delete/<int:tenant_id>',methods=['POST'])
@login_required
@super_required
def delete_tenant(tenant_id):
    c=db(); c.execute('DELETE FROM tenants WHERE id=?',(tenant_id,)); c.commit(); c.close(); flash('Customer account and its portal data were deleted.','warning'); return redirect(url_for('superadmin'))

@app.route('/dashboard')
@login_required
@tenant_required
def dashboard():
    m=int(request.args.get('month',datetime.now().month)); y=int(request.args.get('year',datetime.now().year)); c=db()
    n=c.execute('SELECT COUNT(*) n FROM students WHERE tenant_id=?',(tid(),)).fetchone()['n']
    collected=c.execute('SELECT COALESCE(SUM(amount),0) v FROM payments WHERE tenant_id=? AND month=? AND year=?',(tid(),m,y)).fetchone()['v']
    expenses=c.execute('SELECT COALESCE(SUM(amount),0) v FROM expenses WHERE tenant_id=? AND month=? AND year=?',(tid(),m,y)).fetchone()['v']
    paid=c.execute('SELECT COUNT(*) n FROM payments WHERE tenant_id=? AND month=? AND year=?',(tid(),m,y)).fetchone()['n']
    c.close(); return render_template('dashboard.html',students=n,collected=collected,expenses=expenses,net=collected-expenses,paid=paid,m=m,y=y)

@app.route('/students')
@login_required
@tenant_required
def students():
    q=request.args.get('q','').strip(); c=db(); like=f'%{q}%'
    rows=c.execute('''SELECT * FROM students WHERE tenant_id=? AND (student_name LIKE ? OR father_name LIKE ? OR family_id LIKE ? OR contact LIKE ?) ORDER BY student_name''',(tid(),like,like,like,like)).fetchall(); c.close()
    return render_template('students.html',rows=rows,q=q)

@app.route('/students/save',methods=['POST'])
@login_required
@tenant_required
def save_student():
    sid=request.form.get('id'); vals=(request.form.get('student_name','').strip(),request.form.get('father_name',''),request.form.get('address',''),request.form.get('class_name',''),request.form.get('contact',''),request.form.get('dob',''),int(request.form.get('bus_no') or 0),request.form.get('family_id',''),float(request.form.get('monthly_fee') or 0),request.form.get('join_date',''))
    if not vals[0]: flash('Student name is required.','danger'); return redirect(url_for('students'))
    c=db()
    if sid: c.execute('UPDATE students SET student_name=?,father_name=?,address=?,class_name=?,contact=?,dob=?,bus_no=?,family_id=?,monthly_fee=?,join_date=? WHERE id=? AND tenant_id=?',(*vals,int(sid),tid()))
    else: c.execute('INSERT INTO students(tenant_id,student_name,father_name,address,class_name,contact,dob,bus_no,family_id,monthly_fee,join_date) VALUES(?,?,?,?,?,?,?,?,?,?,?)',(tid(),*vals))
    c.commit(); c.close(); return redirect(url_for('students'))

@app.route('/students/delete/<int:sid>',methods=['POST'])
@login_required
@tenant_required
def delete_student(sid):
    c=db(); c.execute('DELETE FROM students WHERE id=? AND tenant_id=?',(sid,tid())); c.commit(); c.close(); return redirect(url_for('students'))

@app.route('/fees',methods=['GET','POST'])
@login_required
@tenant_required
def fees():
    m=int(request.values.get('month',datetime.now().month)); y=int(request.values.get('year',datetime.now().year)); q=request.values.get('q','').strip(); c=db()
    students=c.execute('SELECT * FROM students WHERE tenant_id=? AND (student_name LIKE ? OR father_name LIKE ? OR family_id LIKE ? OR contact LIKE ?) ORDER BY student_name',(tid(),f'%{q}%',f'%{q}%',f'%{q}%',f'%{q}%')).fetchall()
    payments={r['student_id']:r for r in c.execute('SELECT * FROM payments WHERE tenant_id=? AND month=? AND year=?',(tid(),m,y)).fetchall()}
    c.close(); return render_template('fees.html',students=students,payments=payments,m=m,y=y,q=q)

@app.route('/fees/receive',methods=['POST'])
@login_required
@tenant_required
def receive_fee():
    sid=int(request.form['student_id']); m=int(request.form['month']); y=int(request.form['year']); amount=float(request.form.get('amount') or 0); date=request.form.get('payment_date') or datetime.now().strftime('%Y-%m-%d')
    if amount<=0: flash('Enter an amount greater than zero.','danger'); return redirect(url_for('fees',month=m,year=y))
    c=db(); student=c.execute('SELECT * FROM students WHERE id=? AND tenant_id=?',(sid,tid())).fetchone(); old=c.execute('SELECT * FROM payments WHERE student_id=? AND month=? AND year=?',(sid,m,y)).fetchone()
    if not student: c.close(); abort(404)
    if old: c.execute('UPDATE payments SET amount=?,payment_date=?,notes=?,created_by=? WHERE id=?',(amount,date,request.form.get('notes',''),session['username'],old['id'])); rid=old['id']
    else:
        receipt=make_receipt(); cur=c.execute('INSERT INTO payments(tenant_id,student_id,month,year,amount,payment_date,receipt_no,notes,created_by) VALUES(?,?,?,?,?,?,?,?,?)',(tid(),sid,m,y,amount,date,receipt,request.form.get('notes',''),session['username'])); rid=cur.lastrowid
    c.commit(); c.close(); return redirect(url_for('receipt',pid=rid))

@app.route('/receipt/<int:pid>')
@login_required
@tenant_required
def receipt(pid):
    c=db(); p=c.execute('SELECT p.*,s.student_name,s.father_name,s.class_name,s.family_id,s.bus_no,s.monthly_fee,s.contact FROM payments p JOIN students s ON s.id=p.student_id WHERE p.id=? AND p.tenant_id=?',(pid,tid())).fetchone(); c.close()
    if not p: abort(404)
    return render_template('receipt.html',p=p)

@app.route('/receipt/<int:pid>/print')
@login_required
@tenant_required
def receipt_print(pid):
    c=db(); p=c.execute('SELECT p.*,s.student_name,s.father_name,s.class_name,s.family_id,s.bus_no,s.monthly_fee,s.contact FROM payments p JOIN students s ON s.id=p.student_id WHERE p.id=? AND p.tenant_id=?',(pid,tid())).fetchone(); c.close()
    if not p: abort(404)
    return render_template('receipt_print.html',p=p)

@app.route('/expenses',methods=['GET','POST'])
@login_required
@tenant_required
def expenses():
    m=int(request.values.get('month',datetime.now().month)); y=int(request.values.get('year',datetime.now().year)); c=db()
    if request.method=='POST':
        c.execute('INSERT INTO expenses(tenant_id,expense_date,month,year,category,description,amount,notes,created_by) VALUES(?,?,?,?,?,?,?,?,?)',(tid(),request.form.get('expense_date'),m,y,request.form.get('category'),request.form.get('description',''),float(request.form.get('amount') or 0),request.form.get('notes',''),session['username'])); c.commit()
    rows=c.execute('SELECT * FROM expenses WHERE tenant_id=? AND month=? AND year=? ORDER BY expense_date DESC',(tid(),m,y)).fetchall(); total=sum(r['amount'] for r in rows); c.close()
    return render_template('expenses.html',rows=rows,total=total,m=m,y=y,expense_types=EXPENSES)

@app.route('/expenses/delete/<int:eid>',methods=['POST'])
@login_required
@tenant_required
def delete_expense(eid):
    c=db(); c.execute('DELETE FROM expenses WHERE id=? AND tenant_id=?',(eid,tid())); c.commit(); c.close(); return redirect(url_for('expenses',month=request.args.get('month',datetime.now().month),year=request.args.get('year',datetime.now().year)))

@app.route('/reports')
@login_required
@tenant_required
def reports():
    m=int(request.args.get('month',datetime.now().month)); y=int(request.args.get('year',datetime.now().year)); c=db()
    rows=c.execute('''SELECT s.student_name,s.father_name,s.class_name,s.family_id,s.monthly_fee,COALESCE(p.amount,0) paid,MAX(p.payment_date) payment_date,MAX(p.receipt_no) receipt_no FROM students s LEFT JOIN payments p ON p.student_id=s.id AND p.month=? AND p.year=? WHERE s.tenant_id=? GROUP BY s.id ORDER BY s.student_name''',(m,y,tid())).fetchall(); c.close()
    total_fee=sum(r['monthly_fee'] or 0 for r in rows); total_paid=sum(r['paid'] or 0 for r in rows); outstanding=max(total_fee-total_paid,0)
    return render_template('reports.html',rows=rows,m=m,y=y,total_fee=total_fee,total_paid=total_paid,outstanding=outstanding)

@app.route('/staff')
@login_required
@tenant_required
def staff():
    c=db(); rows=c.execute('SELECT * FROM staff WHERE tenant_id=? ORDER BY staff_name',(tid(),)).fetchall(); c.close(); return render_template('staff.html',rows=rows)

@app.route('/staff/save',methods=['POST'])
@login_required
@tenant_required
def save_staff():
    sid=request.form.get('id'); vals=(request.form.get('staff_name'),request.form.get('designation'),request.form.get('contact'),request.form.get('visa_expiry'),request.form.get('insurance_expiry'),request.form.get('notes')); c=db()
    if sid: c.execute('UPDATE staff SET staff_name=?,designation=?,contact=?,visa_expiry=?,insurance_expiry=?,notes=? WHERE id=? AND tenant_id=?',(*vals,sid,tid()))
    else: c.execute('INSERT INTO staff(tenant_id,staff_name,designation,contact,visa_expiry,insurance_expiry,notes) VALUES(?,?,?,?,?,?,?)',(tid(),*vals))
    c.commit(); c.close(); return redirect(url_for('staff'))

@app.route('/staff/delete/<int:sid>',methods=['POST'])
@login_required
@tenant_required
def delete_staff(sid):
    c=db(); c.execute('DELETE FROM staff WHERE id=? AND tenant_id=?',(sid,tid())); c.commit(); c.close(); return redirect(url_for('staff'))

@app.route('/drivers')
@login_required
@tenant_required
def drivers():
    c=db(); rows=c.execute('SELECT * FROM drivers_vehicles WHERE tenant_id=? ORDER BY vehicle_number',(tid(),)).fetchall(); c.close(); return render_template('drivers.html',rows=rows)

@app.route('/drivers/save',methods=['POST'])
@login_required
@tenant_required
def save_driver():
    did=request.form.get('id'); vals=(request.form.get('vehicle_number'),request.form.get('driver_name'),request.form.get('vehicle_insurance_expiry'),request.form.get('vehicle_license_expiry'),request.form.get('driver_license_expiry'),request.form.get('driver_visa_expiry'),request.form.get('notes')); c=db()
    if did: c.execute('UPDATE drivers_vehicles SET vehicle_number=?,driver_name=?,vehicle_insurance_expiry=?,vehicle_license_expiry=?,driver_license_expiry=?,driver_visa_expiry=?,notes=? WHERE id=? AND tenant_id=?',(*vals,did,tid()))
    else: c.execute('INSERT INTO drivers_vehicles(tenant_id,vehicle_number,driver_name,vehicle_insurance_expiry,vehicle_license_expiry,driver_license_expiry,driver_visa_expiry,notes) VALUES(?,?,?,?,?,?,?,?)',(tid(),*vals))
    c.commit(); c.close(); return redirect(url_for('drivers'))

@app.route('/drivers/delete/<int:did>',methods=['POST'])
@login_required
@tenant_required
def delete_driver(did):
    c=db(); c.execute('DELETE FROM drivers_vehicles WHERE id=? AND tenant_id=?',(did,tid())); c.commit(); c.close(); return redirect(url_for('drivers'))

@app.route('/admin/users',methods=['GET','POST'])
@login_required
@tenant_required
def users():
    c=db()
    if request.method=='POST':
        u=request.form.get('username','').strip(); p=request.form.get('password','')
        try: c.execute('INSERT INTO memberships(tenant_id,username,password_hash,role,active) VALUES(?,?,?,?,1)',(tid(),u,generate_password_hash(p),'Staff')); c.commit(); flash('User created.','success')
        except sqlite3.IntegrityError: flash('That username already exists for this portal.','danger')
    rows=c.execute('SELECT id,username,role,active,created_at FROM memberships WHERE tenant_id=? ORDER BY id',(tid(),)).fetchall(); c.close(); return render_template('users.html',rows=rows)

@app.route('/admin/users/toggle/<int:uid>',methods=['POST'])
@login_required
@tenant_required
def toggle_user(uid):
    c=db(); c.execute('UPDATE memberships SET active=1-active WHERE id=? AND tenant_id=?',(uid,tid())); c.commit(); c.close(); return redirect(url_for('users'))

@app.route('/admin/users/reset/<int:uid>',methods=['POST'])
@login_required
@tenant_required
def reset_user(uid):
    p=request.form.get('password',''); c=db(); c.execute('UPDATE memberships SET password_hash=? WHERE id=? AND tenant_id=?',(generate_password_hash(p),uid,tid())); c.commit(); c.close(); return redirect(url_for('users'))

@app.route('/admin/users/delete/<int:uid>',methods=['POST'])
@login_required
@tenant_required
def delete_user(uid):
    c=db(); c.execute('DELETE FROM memberships WHERE id=? AND tenant_id=? AND role<>"Admin"',(uid,tid())); c.commit(); c.close(); return redirect(url_for('users'))

@app.route('/export.csv')
@login_required
@tenant_required
def export_csv():
    import csv
    c=db(); rows=c.execute('SELECT student_name,father_name,address,class_name,contact,dob,bus_no,family_id,monthly_fee,join_date FROM students WHERE tenant_id=? ORDER BY student_name',(tid(),)).fetchall(); c.close()
    s=io.StringIO(); w=csv.writer(s); w.writerow(['Student Name','Father Name','Address','Class','Contact','DOB','Bus No','Family ID','Monthly Fee','Join Date']); [w.writerow(list(r)) for r in rows]; data=io.BytesIO(s.getvalue().encode('utf-8-sig')); return send_file(data,as_attachment=True,download_name='students_export.csv',mimetype='text/csv')

if __name__=='__main__': app.run(host='0.0.0.0',port=int(os.environ.get('PORT',5000)),debug=True)
