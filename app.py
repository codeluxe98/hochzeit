from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
import uuid
from datetime import datetime

app = Flask(__name__)
app.config.from_object('config.Config')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'admin_login'

class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

class Guest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    attending = db.Column(db.Boolean)
    comment = db.Column(db.Text)
    upload_token = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))

class Photo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    guest_id = db.Column(db.Integer, db.ForeignKey('guest.id'))
    filename = db.Column(db.String(200))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return Admin.query.get(int(user_id))


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/rsvp', methods=['GET', 'POST'])
def rsvp():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        attending = request.form.get('attending') == 'yes'
        comment = request.form.get('comment')
        guest = Guest(name=name, email=email, attending=attending, comment=comment)
        db.session.add(guest)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('rsvp.html')

@app.route('/upload/<token>', methods=['GET', 'POST'])
def upload(token):
    guest = Guest.query.filter_by(upload_token=token).first_or_404()
    if request.method == 'POST':
        file = request.files['photo']
        if file:
            filename = f"{uuid.uuid4()}_{file.filename}"
            upload_path = os.path.join('uploads', filename)
            os.makedirs('uploads', exist_ok=True)
            file.save(upload_path)
            photo = Photo(guest_id=guest.id, filename=filename)
            db.session.add(photo)
            db.session.commit()
            return redirect(url_for('upload', token=token))
    return render_template('upload.html', guest=guest)

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        admin = Admin.query.filter_by(username=username).first()
        if admin and check_password_hash(admin.password_hash, password):
            login_user(admin)
            return redirect(url_for('admin_dashboard'))
    return render_template('login.html')

@app.route('/admin/logout')
@login_required
def admin_logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/admin')
@login_required
def admin_dashboard():
    guests = Guest.query.all()
    photos = Photo.query.all()
    return render_template('admin.html', guests=guests, photos=photos)

if __name__ == '__main__':
    # Bind to all interfaces so the server is reachable from other machines
    app.run(debug=True, host='0.0.0.0')
