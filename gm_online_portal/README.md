# GM International College Management System - Online Web Portal

This is the first web-portal conversion of the Windows application. It includes:
- Super Admin with customer/tenant creation and activate/deactivate control
- Customer/Admin login and portal-specific data isolation
- Student records, Family ID, siblings via Family ID, Bus 1-15, monthly fee
- Fee collection by month/year with receipt number and printable Student/Office copies
- Expenses
- Monthly reports
- Staff/teacher records
- Drivers/vehicles records
- Customer portal user management
- CSV student export

## Test locally
Windows:
1. Install Python 3.11+
2. Open Command Prompt in this folder
3. `py -m venv .venv`
4. `.venv\\Scripts\\activate`
5. `pip install -r requirements.txt`
6. `py app.py`
7. Open `http://127.0.0.1:5000`

Default Super Admin:
- Username: `superadmin`
- Password: `admin123`

Change this password/SECRET_KEY before real deployment.

## Hosting
The next step is to deploy this folder to a free-tier web host. The SQLite database in this version is suitable for testing/local deployment; for a real multi-customer production deployment, we should move the database to a hosted PostgreSQL-compatible service before heavy use.
