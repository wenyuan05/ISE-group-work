from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import bcrypt

app = Flask(__name__)
app.secret_key = 'your-secret-key-123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///library.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# 初始化 Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ------------------------- 数据模型 -------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), default='user')

    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    author = db.Column(db.String(50), nullable=False)
    isbn = db.Column(db.String(20))
    stock = db.Column(db.Integer, default=1)

# ------------------------- 用户加载函数 -------------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ------------------------- 路由定义 -------------------------
@app.route('/')
def index():
    books = Book.query.all()
    return render_template('index.html', books=books)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        flash('用户名或密码错误', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('已退出登录', 'success')
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('用户名已存在', 'danger')
        else:
            user = User(username=username)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash('注册成功，请登录', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/add_book', methods=['GET', 'POST'])
@login_required
def add_book():
    if current_user.role != 'admin':
        flash('无权限操作', 'danger')
        return redirect(url_for('index'))
    if request.method == 'POST':
        title = request.form['title']
        author = request.form['author']
        if not title or not author:
            flash('书名和作者不能为空', 'danger')
            return redirect(url_for('add_book'))
        new_book = Book(title=title, author=author)
        db.session.add(new_book)
        db.session.commit()
        flash('图书添加成功', 'success')
        return redirect(url_for('index'))
    return render_template('add_book.html')

@app.route('/search')
def search():
    keyword = request.args.get('keyword', '')
    if keyword:
        books = Book.query.filter(
            Book.title.contains(keyword) | 
            Book.author.contains(keyword)
        ).all()
    else:
        books = Book.query.all()
    return render_template('index.html', books=books, keyword=keyword)

@app.route('/delete_book/<int:book_id>')
@login_required
def delete_book(book_id):
    if current_user.role != 'admin':
        flash('无权限操作', 'danger')
        return redirect(url_for('index'))
    book = Book.query.get_or_404(book_id)
    db.session.delete(book)
    db.session.commit()
    flash('图书删除成功', 'success')
    return redirect(url_for('index'))

# ------------------------- 初始化数据库 -------------------------
def create_tables():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', role='admin')
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()

if __name__ == '__main__':
    create_tables()
    app.run(debug=True)