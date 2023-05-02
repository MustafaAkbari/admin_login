from flask import Flask, render_template, redirect, url_for, flash
from datetime import datetime as dt
from flask_login import login_required, LoginManager, current_user, login_user, logout_user, UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, EmailField, PasswordField, SelectField
from wtforms.validators import DataRequired, EqualTo, Email, Length, Regexp
from sqlalchemy import exc
from flask_migrate import Migrate
import csv

app = Flask(__name__)
# define a secret key
app.config["SECRET_KEY"] = "this is a payment app"
# database setup
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://root:rose@localhost/payout"
db = SQLAlchemy(app)
app.app_context().push()
migrate = Migrate(app, db)
# flask login stuff
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return Admins.query.get(int(user_id))


########################
######## MODELS ########
########################
# creating an admin model
class Admins(db.Model, UserMixin):
    __tablename__ = "Admins"
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(65), nullable=False)
    username = db.Column(db.String(65), nullable=False, unique=True)
    email = db.Column(db.String(128), nullable=False, unique=True)
    password_hash = db.Column(db.String(128), nullable=False)

    @property
    def password(self):
        raise AttributeError("Password is not a readable content")

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)


# creating a model for refuges
class Refuges(db.Model):
    __tablename__ = "refuges"
    id = db.Column(db.Integer, primary_key=True)
    mid = db.Column(db.String(8), nullable=False, unique=True)
    name = db.Column(db.String(65), nullable=False)
    last_name = db.Column(db.String(65), nullable=False)
    payment = db.Column(db.String(10), nullable=False)
    payment_date = db.Column(db.DateTime, default=dt.utcnow())


########################
######## FORMS #########
########################
# creating an admin registration form
class AdminForm(FlaskForm):
    fullname = StringField("FullName: ", validators=[DataRequired()], render_kw={"placeholder": "FullName"})
    username = StringField("UserName: ", validators=[DataRequired()], render_kw={"placeholder": "UserName"})
    email = EmailField("Email: ", validators=[DataRequired(), Email()], render_kw={"placeholder": "Email"})
    password = PasswordField("Password: ",
                             validators=[DataRequired(), EqualTo("confirm_password", "password must match!")],
                             render_kw={"placeholder": "Password"})
    confirm_password = PasswordField("Confirm Password", validators=[DataRequired()],
                                     render_kw={"placeholder": "Confirm Password"})
    submit = SubmitField("Register")


# creating a login form
class LoginForm(FlaskForm):
    username = StringField("UserName: ", validators=[DataRequired()], render_kw={"placeholder": "UserName"})
    password = PasswordField("Password: ", validators=[DataRequired()], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")


# creating a refuge registration form with his/her payment
class RefugeForm(FlaskForm):
    mid = StringField("MID Number: ", validators=[DataRequired(), Length(min=8, max=8),
                                                  Regexp('^\d{8}$',
                                                         message='Be sure to have 8 digits of number, not character!')],
                      render_kw={"placeholder": "MID Number"})
    name = StringField("Name: ", validators=[DataRequired()], render_kw={"placeholder": "Name"})
    last_name = StringField("Last_name: ", validators=[DataRequired()], render_kw={"placeholder": "Last Name"})
    payment = SelectField("Money Received: ", validators=[DataRequired(), Length(min=2, max=3)],
                          choices=[("Select an option", "select an option"), ("Yes", "Yes"), ("No", "No")])
    submit = SubmitField("Save")


#########################
######## VIEWS ##########
#########################
# creating home view
@app.route("/")
def home():
    return render_template("index.html")


# creating view to register an admin
@app.route("/register_admin", methods=["GET", "POST"])
@login_required
def register_admin():
    form = AdminForm()
    if form.validate_on_submit():
        admin = Admins.query.filter_by(username=form.username.data, email=form.email.data).first()
        try:
            if admin is None:
                hashed_password = generate_password_hash(form.password.data)
                new_admin = Admins(fullname=form.fullname.data,
                                   username=form.username.data,
                                   email=form.email.data,
                                   password_hash=hashed_password)
                db.session.add(new_admin)
                db.session.commit()
                flash(f"An Admin named: {form.fullname.data} registered!", "success")
                return redirect(url_for("register_admin"))
        except exc.IntegrityError:
            db.session.rollback()
            flash("The email address or username was taken!", "warning")
            return redirect(url_for("register_admin"))
    return render_template("register_admin.html", form=form)


# creating a view for admin to login
@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        admin = Admins.query.filter_by(username=form.username.data).first()
        if admin:
            if check_password_hash(admin.password_hash, form.password.data):
                login_user(admin)
                flash("Admin successfully logged in!", "success")
                return redirect(url_for("home"))
            else:
                flash("Password error, try again!", "danger")
                return redirect(url_for("login"))
        else:
            flash("Username is incorrect!", "danger")
    return render_template("login.html", form=form)


# creating a route to logout
@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out from application!")
    return redirect(url_for("login"))


# creating a route for registering refuge's payment
@app.route("/register_refuge", methods=["GET", "POST"])
@login_required
def register_refuge():
    form = RefugeForm()
    if form.validate_on_submit():
        refuge = Refuges.query.filter_by(mid=form.mid.data).first()
        if refuge is None:
            try:
                new_refuge = Refuges(mid=form.mid.data,
                                     name=form.name.data,
                                     last_name=form.last_name.data,
                                     payment=form.payment.data)
                db.session.add(new_refuge)
                db.session.commit()
                flash(f"A person named: {form.name.data} with MID number: {form.mid.data} registered!", "success")
                # Save form data to text file
                with open('form_data.txt', mode='a') as file:
                    file.write(f'Name: {form.name.data}\nLast Name: {form.last_name.data}\n'
                               f'MID Number: {form.mid.data}\nPayment: {form.payment.data}\n\n\n')
                return redirect(url_for("register_refuge"))
            except exc.IntegrityError:
                db.session.rollback()
                flash("An error occurred during the registration. please try again!", "danger")
                return redirect(url_for("register_refuge"))
        else:
            flash(f"There is a person in table with this MID number: {form.mid.data}", "warning")
    return render_template("register_refuge.html", form=form)


# creating a route to list the refuges info
@app.route("/list_refuges")
@login_required
def list_refuges():
    refuges = Refuges.query.order_by(Refuges.name)
    return render_template("list_refuges.html", refuges=refuges)


if __name__ == "__main__":
    app.run(debug=True)
