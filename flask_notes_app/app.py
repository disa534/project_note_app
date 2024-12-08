# app.py (обновленный)

from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = '1234' 

# Определение абсолютного пути к каталогу проекта
basedir = os.path.abspath(os.path.dirname(__file__))

# Обновление URI базы данных с использованием абсолютного пути
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'instance', 'notes.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# Генерация или загрузка ключа для шифрования заметок
KEY_FILE = os.path.join(basedir, 'encryption.key')

def load_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as key_file:
            key = key_file.read()
            # Проверка длины и корректности ключа
            if len(key) != 44:  # 32 байта в Base64 кодировке = 44 символа
                raise ValueError("Некорректный ключ шифрования.")
            return key
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as key_file:
            key_file.write(key)
        return key

try:
    encryption_key = load_or_create_key()
except ValueError as ve:
    print(f"Ошибка загрузки ключа шифрования: {ve}")
    exit(1)

cipher_suite = Fernet(encryption_key)

# Модели
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    notes = db.relationship('Note', backref='owner', lazy=True)

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title_encrypted = db.Column(db.LargeBinary, nullable=False)
    content_encrypted = db.Column(db.LargeBinary, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def get_title(self):
        return cipher_suite.decrypt(self.title_encrypted).decode('utf-8')

    def set_title(self, plaintext):
        self.title_encrypted = cipher_suite.encrypt(plaintext.encode('utf-8'))

    def get_content(self):
        return cipher_suite.decrypt(self.content_encrypted).decode('utf-8')

    def set_content(self, plaintext):
        self.content_encrypted = cipher_suite.encrypt(plaintext.encode('utf-8'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Маршруты
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Проверка наличия пользователя
        if User.query.filter_by(username=username).first():
            flash('Имя пользователя уже существует.', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(username=username, password=hashed_password)

        db.session.add(new_user)
        db.session.commit()

        flash('Регистрация прошла успешно. Войдите в систему.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if not user or not check_password_hash(user.password, password):
            flash('Неправильное имя пользователя или пароль.', 'danger')
            return redirect(url_for('login'))

        login_user(user)
        return redirect(url_for('notes'))

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из системы.', 'info')
    return redirect(url_for('index'))

@app.route('/notes')
@login_required
def notes():
    user_notes = current_user.notes
    decrypted_notes = []
    for note in user_notes:
        decrypted_notes.append({'id': note.id, 'title': note.get_title()})
    return render_template('notes.html', notes=decrypted_notes)

@app.route('/create_note', methods=['GET', 'POST'])
@login_required
def create_note():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        new_note = Note(user_id=current_user.id)
        new_note.set_title(title)
        new_note.set_content(content)

        db.session.add(new_note)
        db.session.commit()

        flash('Заметка создана.', 'success')
        return redirect(url_for('notes'))

    return render_template('create_note.html')

@app.route('/edit_note/<int:note_id>', methods=['GET', 'POST'])
@login_required
def edit_note(note_id):
    note = Note.query.get_or_404(note_id)

    if note.owner != current_user:
        flash('У вас нет прав для редактирования этой заметки.', 'danger')
        return redirect(url_for('notes'))

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        note.set_title(title)
        note.set_content(content)
        db.session.commit()

        flash('Заметка обновлена.', 'success')
        return redirect(url_for('notes'))

    decrypted_title = note.get_title()
    decrypted_content = note.get_content()
    return render_template('edit_note.html', note=note, title=decrypted_title, content=decrypted_content)

@app.route('/view_note/<int:note_id>')
@login_required
def view_note(note_id):
    note = Note.query.get_or_404(note_id)

    if note.owner != current_user:
        flash('У вас нет прав для просмотра этой заметки.', 'danger')
        return redirect(url_for('notes'))

    decrypted_title = note.get_title()
    decrypted_content = note.get_content()
    return render_template('view_note.html', note=note, title=decrypted_title, content=decrypted_content)

@app.route('/delete_note/<int:note_id>', methods=['POST'])
@login_required
def delete_note(note_id):
    note = Note.query.get_or_404(note_id)

    if note.owner != current_user:
        flash('У вас нет прав для удаления этой заметки.', 'danger')
        return redirect(url_for('notes'))

    db.session.delete(note)
    db.session.commit()

    flash('Заметка удалена.', 'info')
    return redirect(url_for('notes'))

if __name__ == '__main__':
    # Создание базы данных, если она не существует
    if not os.path.exists(os.path.join(basedir, 'instance', 'notes.db')):
        os.makedirs(os.path.join(basedir, 'instance'), exist_ok=True)
        with app.app_context():
            db.create_all()
    app.run(debug=True)
