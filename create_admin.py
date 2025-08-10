from getpass import getpass
from app import app, db, Admin
from werkzeug.security import generate_password_hash

username = input('Admin Benutzername: ')
password = getpass('Admin Passwort: ')

with app.app_context():
    db.create_all()
    admin = Admin(username=username, password_hash=generate_password_hash(password))
    db.session.add(admin)
    db.session.commit()
    print('Admin erstellt.')
