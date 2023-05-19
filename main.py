import smtplib
import os
from datetime import datetime

from flask_wtf import FlaskForm
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from wtforms import StringField, PasswordField, SubmitField, BooleanField, EmailField, URLField
from flask_ckeditor import CKEditor, CKEditorField
from wtforms.widgets import TextArea
from wtforms.validators import Length, Email, DataRequired, URL, InputRequired
from flask import Flask, render_template, url_for, request, redirect, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_gravatar import Gravatar
from functools import wraps
from flask import abort

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]
app.app_context().push()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog_post.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)
ckeditor = CKEditor(app)
gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False,
                    force_lower=False, use_ssl=False, base_url=None)

FROM_EMAIL = os.environ["FROM_EMAIL"]
PASSWORD = os.environ["PASSWORD"]
TO_EMAIL = os.environ["TO_EMAIL"]


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ADMIN ONLY DECORATOR
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)

    return decorated_function


# DATABASE TABLES
class User(UserMixin, db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250))
    email = db.Column(db.String(250), unique=True)
    password = db.Column(db.String(250))
    posts = relationship('AllBlogPosts', back_populates='post_author')
    comments = relationship('Comments', back_populates='comment_author')


class AllBlogPosts(db.Model):
    __tablename__ = "all_blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    date = db.Column(db.Date, nullable=False, default="datetime.utcnow")
    body = db.Column(db.Text, nullable=False)
    post_author = relationship('User', back_populates='posts')
    comments = relationship('Comments', back_populates='author_post')

    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))


class Comments(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    comment_author = relationship('User', back_populates='comments')

    post_id = db.Column(db.Integer, db.ForeignKey("all_blog_posts.id"))
    author_post = relationship("AllBlogPosts", back_populates="comments")


class ContactUs(db.Model):
    __tablename__ = "contact_us"
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False, default="datetime.utcnow")
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), nullable=False)
    message = db.Column(db.String(250), nullable=False)

    def to_dict(self) -> dict:
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}


# RUN THIS LINE ONCE TO CREATE THE DATABASE TABLE
# db.create_all()


# FORMS
class LoginForm(FlaskForm):
    email = EmailField('Email', [DataRequired(), Email()])
    password = PasswordField('Password', [DataRequired(), Length(min=8, max=50)])
    remember = BooleanField('Remember me')
    login = SubmitField("Login")


class RegisterForm(LoginForm):
    name = StringField('Name', [DataRequired(), Length(min=2, max=50)])
    agree = BooleanField('Agree', [DataRequired(message="Check to agree to user terms")])
    signup = SubmitField("Sign Up")


class ContactUsForm(FlaskForm):
    name = StringField('Name', [DataRequired(), Length(min=2, max=50)])
    email = EmailField('Email', [DataRequired(), Email()])
    message = StringField(label='Message', widget=TextArea(), validators=[DataRequired(), Length(min=10)])
    send = SubmitField("Send")


class CreateBlogPostForm(FlaskForm):
    title = StringField('Title', [DataRequired(), Length(min=3, max=50)])
    subtitle = StringField('Subtitle', [DataRequired(), Length(min=3, max=120)])
    img_url = URLField("Image URL", validators=[DataRequired(), URL()])
    new_blog_post = CKEditorField("Write Your Post Here", [InputRequired(), Length(min=50, max=5000)])
    create = SubmitField("Create Post")


class PostEditForm(CreateBlogPostForm):
    new_body = CKEditorField("Edit Your Post Here", [InputRequired(), Length(min=50, max=5000)])
    update = SubmitField("Update Post")


class CommentForm(FlaskForm):
    text = CKEditorField("Write Your Comment Here", [InputRequired(), Length(min=1, max=1000)])
    submit = SubmitField("Submit Comment")


@app.route("/")
def home():
    all_blog_post = db.session.query(AllBlogPosts).all()
    return render_template('index.html', all_post=all_blog_post, logged_in=current_user.is_authenticated,
                           current_user=current_user)


@app.route('/register', methods=["GET", "POST"])
def register():
    register_form = RegisterForm()
    if request.method == "POST" and register_form.validate_on_submit():
        if User.query.filter_by(email=request.form.get('email')).first():
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))
        new_user = User()
        new_user.date = datetime.now().date()
        new_user.name = request.form.get("name")
        new_user.email = request.form.get("email")
        new_user.password = generate_password_hash(request.form.get('password'), method='pbkdf2:sha256', salt_length=8)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("secrets", name=new_user.name))
    return render_template("register.html", logged_in=current_user.is_authenticated, current_user=current_user,
                           form=register_form)


@app.route('/login', methods=["GET", "POST"])
def login():
    login_form = LoginForm()
    if request.method == "POST" and login_form.validate_on_submit():
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('secrets'))
    return render_template("login.html", logged_in=current_user.is_authenticated,
                           current_user=current_user, form=login_form)


@app.route('/secrets')
@login_required
def secrets():
    all_post = db.session.query(AllBlogPosts).all()
    return render_template("secrets.html", all_post=all_post,
                           name=current_user.name, logged_in=True, current_user=current_user)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route("/read-post/<int:post_id>", methods=["GET", "POST"])
@login_required
def read_post(post_id):
    comment_form = CommentForm()
    post_to_read = db.session.query(AllBlogPosts).filter_by(id=int(post_id)).first()
    if request.method == "POST" and comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            return redirect(url_for("login"))
        else:
            new_comment = Comments(text=request.form["text"],
                                   comment_author=current_user,
                                   author_post=post_to_read
                                   )
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for("secrets"))
    return render_template("read_post.html", logged_in=current_user.is_authenticated, post=post_to_read,
                           name=current_user.name, form=comment_form)


@app.route("/add", methods=["GET", "POST"])
@login_required
@admin_only
def add():
    create_blog_post_form = CreateBlogPostForm()
    if request.method == "POST" and create_blog_post_form.validate_on_submit():
        new_post = AllBlogPosts(
            title=request.form["title"],
            subtitle=request.form["subtitle"],
            post_author=current_user,
            img_url=request.form["img_url"],
            date=datetime.now().date(),
            body=request.form["new_blog_post"]
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("secrets"))
    else:
        return render_template("add.html", form=create_blog_post_form, logged_in=current_user.is_authenticated,
                               current_user=current_user)

# TODO: ADD LIKES AND DISLIKE TO BLOG POSTS


@app.route("/edit", methods=["GET", "POST"])
@login_required
@admin_only
def edit():
    post_edit_form = PostEditForm()
    if request.method == "POST":
        # UPDATE RECORD
        post_id = request.args.get('post_id')
        post_to_update = db.session.query(AllBlogPosts).get(int(post_id))
        post_to_update.subtitle = request.form["subtitle"]
        post_to_update.body = request.form["new_body"]
        db.session.commit()
        return redirect(url_for('secrets'))
    post_id = request.args.get('post_id')
    post_selected = db.session.query(AllBlogPosts).get(int(post_id))
    return render_template("edit.html", post=post_selected, form=post_edit_form,
                           logged_in=current_user.is_authenticated, current_user=current_user)


@app.route("/delete/<int:post_id>")
@login_required
@admin_only
def delete(post_id):
    post_to_delete = AllBlogPosts.query.get(int(post_id))
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('secrets'))


@app.route("/contact-us", methods=['GET', 'POST'])
@login_required
def contact_us():
    contact_us_form = ContactUsForm()
    if request.method == "POST":
        name = contact_us_form.name.data
        email = contact_us_form.email.data
        message = contact_us_form.message.data
        message_to_us = ContactUs(
            name=name,
            email=email,
            message=message,
            date=datetime.now().date()
        )
        db.session.add(message_to_us)
        db.session.commit()

        # SEND MESSAGE TO OUR EMAIL
        our_gmail = FROM_EMAIL
        password = PASSWORD
        email = TO_EMAIL
        message = f"""
        NAME: {name}
        EMAIL: {email}
        {message}
"""
        with smtplib.SMTP(host="smtp.gmail.com") as connection:
            connection.starttls()
            connection.login(our_gmail, password)
            connection.sendmail(
                from_addr=our_gmail,
                to_addrs=email,
                msg=f"Subject:Blog Post\n\n{message}".encode('utf-8'))
        return redirect(url_for('secrets'))
    return render_template("contact_us.html", form=contact_us_form, current_user=current_user,
                           logged_in=current_user.is_authenticated)


@app.route("/about")
def about_us():
    return render_template('about_us.html', logged_in=current_user.is_authenticated, current_user=current_user)


@app.route("/faqs")
def faqs():
    return render_template('faqs.html', logged_in=current_user.is_authenticated, current_user=current_user)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
