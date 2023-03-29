from flask import g, Flask, render_template, redirect, url_for, flash, request, abort
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, URL
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm
from flask_gravatar import Gravatar
from functools import wraps
from sqlalchemy.ext.declarative import declarative_base
from flask_ckeditor import CKEditorField
from flask_gravatar import Gravatar
import os


Base = declarative_base()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)
EMAIL = 'https://www.gravatar.com/avatar/205e460b479e2e5b48aec07710c08d50?s=200'

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


def admin_only(f):
    @wraps(f)
    def wrapper_function(*args, **kwargs):
        if current_user.id == 1:
            return f(*args, **kwargs)
        abort(403, description="Resource not found")

    return wrapper_function


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


##CONFIGURE TABLES

class User(UserMixin, db.Model):
    __tablename__ = "User"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    posts = relationship('BlogPost', back_populates="author")
    comments = relationship('Comment', back_populates="author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('User.id'))
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author = relationship("User", back_populates="posts")
    comments = relationship('Comment', back_populates="posts")


class Comment(UserMixin, db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('User.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    text = db.Column(db.String(1000))
    author = relationship("User", back_populates="comments")
    posts = relationship('BlogPost', back_populates="comments")


db.create_all()


class RegisterForm(FlaskForm):
    email = StringField("Your Email", validators=[DataRequired()])
    password = StringField("Your Password", validators=[DataRequired()])
    name = StringField("Your name", validators=[DataRequired()])
    submit = SubmitField("Submit")


class LoginForm(FlaskForm):
    email = StringField("Your Email", validators=[DataRequired()])
    password = StringField("Your Password", validators=[DataRequired()])
    submit = SubmitField("Submit")


class CommentForm(FlaskForm):
    comment = CKEditorField("Comment", validators=[DataRequired()])
    submit = SubmitField("Submit Comment")


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    if current_user.is_authenticated:
        if current_user.id == 1:
            print(current_user)
            return render_template("index.html", all_posts=posts, logged_in=True, admin=True)
        return render_template("index.html", all_posts=posts, logged_in=True)
    return render_template("index.html", all_posts=posts, logged_in=False)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        existing_email = request.form.get("email")
        if User.query.filter_by(email=existing_email).first() is None:
            new_user = User(
                email=request.form.get("email"),
                password=generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8),
                name=request.form.get("name"),
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('get_all_posts'))
        else:
            flash('Email already exists. Try to Login.')
            return redirect(url_for('login', logged_in=False))
    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = request.form.get("email")
        password = request.form.get("password")
        user_to_check = User.query.filter_by(email=email).first()
        if user_to_check:
            if check_password_hash(user_to_check.password, password):
                login_user(user_to_check)
                return redirect(url_for('get_all_posts'))
            else:
                flash('Incorrect password entered.')
                return redirect(url_for('login', logged_in=False))
        else:
            flash('Email does not exist')
            return redirect(url_for('login', logged_in=False))
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = CommentForm()
    gravatar_url = gravatar(EMAIL, size=20)
    requested_post = BlogPost.query.get(post_id)
    comments = Comment.query.filter_by(posts=requested_post).all()

    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to be logged in.")
            return redirect(url_for('login'))\

        new_comment = Comment(
            text=form.comment.data,
            author=current_user,
            posts=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
    return render_template("post.html", post=requested_post, form=form, current_user=current_user, comments=comments, gravatar=gravatar_url)


@app.route("/about")
def about():
    if current_user.is_authenticated:
        return render_template("about.html", current_user=current_user)
    return render_template("about.html")


@app.route("/contact")
def contact():
    if current_user.is_authenticated:
        return render_template("contact.html", current_user=current_user)
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        print(current_user)
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, current_user=current_user)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=current_user,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    print(current_user)
    return render_template("make-post.html", form=edit_form, is_edit=True, current_user=current_user)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
