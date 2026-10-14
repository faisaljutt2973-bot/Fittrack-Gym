import hashlib
import hmac
import os
import re
import secrets
import smtplib
import ssl
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
from urllib.parse import urlparse

import stripe
from bson import ObjectId
from pymongo import MongoClient, ReturnDocument
from pymongo.errors import DuplicateKeyError
from flask import Flask, abort, flash, jsonify, redirect, render_template, request, send_from_directory, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash


ROOT_DIR = Path(__file__).resolve().parent
ALLOWED_STATIC_SUFFIXES = {".css", ".html", ".ico", ".jpeg", ".jpg", ".js", ".png", ".svg", ".webp"}
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PHONE_PATTERN = re.compile(r"^\+?[1-9]\d{6,14}$")
PASSWORD_MIN_LENGTH = 12
RESET_TOKEN_TTL = timedelta(minutes=30)
RESET_REQUEST_MESSAGE = (
    "If an account matches that email and email delivery is configured, "
    "a password reset link will arrive shortly."
)

PRODUCTS = {
    "lean-protein": {
        "id": "lean-protein",
        "name": "Lean Protein",
        "category": "Nutrition",
        "description": "High-quality whey protein to support lean muscle growth and quick recovery.",
        "image": "https://images.unsplash.com/photo-1517838277536-f5f99be501cd?auto=format&fit=crop&w=900&q=80",
        "image_alt": "Protein powder",
        "price_cents": 3900,
        "currency": "usd",
    },
    "grip-set": {
        "id": "grip-set",
        "name": "Grip Set",
        "category": "Accessories",
        "description": "Performance gloves and straps built for stronger grips during heavy lifts and intense sessions.",
        "image": "https://images.unsplash.com/photo-1534438327276-14e5300c3a48?auto=format&fit=crop&w=900&q=80",
        "image_alt": "Gym training equipment",
        "price_cents": 2800,
        "currency": "usd",
    },
    "recovery-kit": {
        "id": "recovery-kit",
        "name": "Recovery Kit",
        "category": "Recovery",
        "description": "Foam roller, massage ball, and support tools to improve mobility and post-workout recovery.",
        "image": "https://images.unsplash.com/photo-1534438327276-14e5300c3a48?auto=format&fit=crop&w=900&q=80",
        "image_alt": "Fitness and recovery equipment",
        "price_cents": 4200,
        "currency": "usd",
    },
}

app = Flask(__name__, template_folder=str(ROOT_DIR / "templates"))
app.config.update(
    SECRET_KEY=os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32),
    MONGO_URI=os.environ.get(
        "MONGODB_URI",
        "mongodb+srv://faisaljutt2973_db_user:Rc61yoAB4uwweJ3U@cluster1.j1tmeoi.mongodb.net/",
    ),
    MONGO_DB_NAME=os.environ.get("MONGODB_DATABASE", "fittrack_gym"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("PUBLIC_BASE_URL", "").lower().startswith("https://"),
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
)


def get_db():
    client = app.config.get("MONGO_CLIENT")
    if client is None:
        client = MongoClient(app.config["MONGO_URI"])
        app.config["MONGO_CLIENT"] = client

    database = client[app.config["MONGO_DB_NAME"]]
    index_key = (id(client), database.name)
    if app.extensions.get("fittrack_mongo_indexes_key") != index_key:
        database.users.create_index("email", unique=True)
        database.users.create_index("phone", unique=True)
        database.users.create_index("password_reset.token_hash", unique=True, sparse=True)
        app.extensions["fittrack_mongo_indexes_key"] = index_key
    return database


def normalize_phone(value):
    phone = re.sub(r"[\s().-]", "", value)
    return phone if PHONE_PATTERN.fullmatch(phone) else None


def valid_csrf_token():
    supplied = request.form.get("csrf_token", "")
    expected = session.get("csrf_token", "")
    return bool(supplied and expected and hmac.compare_digest(supplied, expected))


def csrf_token():
    token = session.get("csrf_token")
    if token is None:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def password_reset_email_settings():
    required = ("SMTP_HOST", "SMTP_FROM", "PUBLIC_BASE_URL")
    settings = {name: os.environ.get(name, "").strip() for name in required}
    if not all(settings.values()):
        return None

    base_url = settings["PUBLIC_BASE_URL"].rstrip("/")
    parsed_base_url = urlparse(base_url)
    if (
        parsed_base_url.scheme not in {"http", "https"}
        or not parsed_base_url.netloc
        or parsed_base_url.username
        or parsed_base_url.password
        or parsed_base_url.query
        or parsed_base_url.fragment
    ):
        return None

    settings["PUBLIC_BASE_URL"] = base_url
    settings["SMTP_PORT"] = os.environ.get("SMTP_PORT", "587")
    settings["SMTP_USERNAME"] = os.environ.get("SMTP_USERNAME", "").strip()
    settings["SMTP_PASSWORD"] = os.environ.get("SMTP_PASSWORD", "")
    if bool(settings["SMTP_USERNAME"]) != bool(settings["SMTP_PASSWORD"]):
        return None
    return settings


def send_password_reset_email(recipient, reset_url, settings):
    message = EmailMessage()
    message["Subject"] = "Reset your FITTRACK GYM password"
    message["From"] = settings["SMTP_FROM"]
    message["To"] = recipient
    message.set_content(
        "We received a request to reset your FITTRACK GYM password.\n\n"
        f"Use this link within 30 minutes to choose a new password:\n{reset_url}\n\n"
        "If you did not request this, you can ignore this email."
    )

    context = ssl.create_default_context()
    with smtplib.SMTP(settings["SMTP_HOST"], int(settings["SMTP_PORT"]), timeout=15) as smtp:
        smtp.starttls(context=context)
        if settings["SMTP_USERNAME"]:
            smtp.login(settings["SMTP_USERNAME"], settings["SMTP_PASSWORD"])
        smtp.send_message(message)


def csrf_error_response():
    return render_template(
        "auth_message.html",
        title="Form expired",
        message="This form could not be verified. Reload the page and try again.",
        action_url=url_for("login_page"),
        action_label="Back to login",
    ), 400


def render_auth_template(template, **context):
    return render_template(template, csrf_token=csrf_token(), **context)


def get_logged_in_user():
    user_id = session.get("user_id")
    auth_version = session.get("auth_version")
    if not isinstance(user_id, str) or not ObjectId.is_valid(user_id) or not isinstance(auth_version, int):
        return None

    user = get_db().users.find_one(
        {"_id": ObjectId(user_id)},
        {"first_name": 1, "last_name": 1, "email": 1, "phone": 1, "goal": 1, "auth_version": 1},
    )
    if user is None or user["auth_version"] != auth_version:
        session.clear()
        return None
    return user


def stripe_secret_key():
    return os.environ.get("STRIPE_SECRET_KEY", "").strip()


@app.get("/")
def index():
    return send_from_directory(ROOT_DIR, "index.html")


@app.get("/api/products")
def list_products():
    return jsonify(list(PRODUCTS.values()))


@app.route("/signup.html", methods=["GET", "POST"])
def signup_page():
    if request.method == "GET":
        return render_auth_template("signup.html")
    if not valid_csrf_token():
        return csrf_error_response()

    first_name = request.form.get("first_name", "").strip()
    last_name = request.form.get("last_name", "").strip()
    email = request.form.get("email", "").strip().lower()
    phone = normalize_phone(request.form.get("phone", ""))
    password = request.form.get("password", "")
    goal = request.form.get("goal", "").strip()
    valid_goals = {"Build muscle", "Lose weight", "Improve endurance", "General fitness"}

    if not first_name or not last_name:
        flash("Enter your first and last name.", "error")
    elif len(first_name) > 80 or len(last_name) > 80:
        flash("Names must be 80 characters or fewer.", "error")
    elif not EMAIL_PATTERN.fullmatch(email) or len(email) > 254:
        flash("Enter a valid email address.", "error")
    elif phone is None:
        flash("Enter a valid phone number, including its country code.", "error")
    elif len(password) < PASSWORD_MIN_LENGTH:
        flash(f"Use a password with at least {PASSWORD_MIN_LENGTH} characters.", "error")
    elif goal not in valid_goals:
        flash("Choose a valid fitness goal.", "error")
    else:
        try:
            result = get_db().users.insert_one(
                {
                    "first_name": first_name,
                    "last_name": last_name,
                    "email": email,
                    "phone": phone,
                    "password_hash": generate_password_hash(password),
                    "goal": goal,
                    "auth_version": 1,
                    "created_at": datetime.now(timezone.utc),
                }
            )
        except DuplicateKeyError:
            flash("An account already uses that email address or phone number.", "error")
        else:
            session.clear()
            session["user_id"] = str(result.inserted_id)
            session["auth_version"] = 1
            session.permanent = True
            flash("Your FITTRACK account is ready.", "success")
            return redirect(url_for("account_page"))

    return render_auth_template("signup.html"), 400


@app.route("/login.html", methods=["GET", "POST"])
def login_page():
    if request.method == "GET":
        return render_auth_template("login.html")
    if not valid_csrf_token():
        return csrf_error_response()

    identifier = request.form.get("identifier", "").strip()
    password = request.form.get("password", "")
    normalized_phone = normalize_phone(identifier)
    lookup = normalized_phone or identifier.lower()

    user = get_db().users.find_one(
        {"$or": [{"email": lookup.lower()}, {"phone": lookup}]},
        {"password_hash": 1, "auth_version": 1},
    )

    if user is None or not check_password_hash(user["password_hash"], password):
        flash("The email/phone number or password is incorrect.", "error")
        return render_auth_template("login.html"), 401

    session.clear()
    session["user_id"] = str(user["_id"])
    session["auth_version"] = user["auth_version"]
    session.permanent = True
    return redirect(url_for("account_page"))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "GET":
        return render_auth_template("forgot_password.html")
    if not valid_csrf_token():
        return csrf_error_response()

    email = request.form.get("email", "").strip().lower()
    settings = password_reset_email_settings()
    if not settings:
        app.logger.error("Password reset email is unavailable because SMTP/PUBLIC_BASE_URL is not configured.")
        flash(RESET_REQUEST_MESSAGE, "success")
        return render_auth_template("forgot_password.html")

    if EMAIL_PATTERN.fullmatch(email) and len(email) <= 254:
        db = get_db()
        user = db.users.find_one({"email": email}, {"email": 1})
        if user:
            token = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
            created_at = datetime.now(timezone.utc)
            db.users.update_one(
                {"_id": user["_id"]},
                {
                    "$set": {
                        "password_reset": {
                            "token_hash": token_hash,
                            "expires_at": created_at + RESET_TOKEN_TTL,
                            "created_at": created_at,
                        }
                    }
                },
            )
            reset_url = (
                f"{settings['PUBLIC_BASE_URL']}"
                f"{url_for('reset_password', token=token)}"
            )
            try:
                send_password_reset_email(user["email"], reset_url, settings)
            except (OSError, smtplib.SMTPException, ValueError):
                app.logger.exception("Sending a FITTRACK password reset email failed.")
                db.users.update_one(
                    {"_id": user["_id"], "password_reset.token_hash": token_hash},
                    {"$unset": {"password_reset": ""}},
                )

    flash(RESET_REQUEST_MESSAGE, "success")
    return render_auth_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    db = get_db()
    user = db.users.find_one(
        {"password_reset.token_hash": token_hash},
        {"password_reset.expires_at": 1},
    )
    reset = user.get("password_reset") if user else None
    now = datetime.now(timezone.utc)

    expires_at = reset["expires_at"] if reset else None
    if expires_at is not None and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if reset is None or expires_at <= now:
        if reset is not None:
            db.users.update_one(
                {"_id": user["_id"], "password_reset.token_hash": token_hash},
                {"$unset": {"password_reset": ""}},
            )
        return render_auth_template("reset_password.html", token=token, token_valid=False), 400

    if request.method == "GET":
        return render_auth_template("reset_password.html", token=token, token_valid=True)
    if not valid_csrf_token():
        return csrf_error_response()

    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")
    if len(password) < PASSWORD_MIN_LENGTH:
        flash(f"Use a password with at least {PASSWORD_MIN_LENGTH} characters.", "error")
        return render_auth_template("reset_password.html", token=token, token_valid=True), 400
    if password != confirm_password:
        flash("The passwords do not match.", "error")
        return render_auth_template("reset_password.html", token=token, token_valid=True), 400

    updated_user = db.users.find_one_and_update(
        {
            "_id": user["_id"],
            "password_reset.token_hash": token_hash,
            "password_reset.expires_at": {"$gt": now},
        },
        {
            "$set": {"password_hash": generate_password_hash(password)},
            "$inc": {"auth_version": 1},
            "$unset": {"password_reset": ""},
        },
        return_document=ReturnDocument.AFTER,
        projection={"_id": 1},
    )
    if updated_user is None:
        return render_auth_template("reset_password.html", token=token, token_valid=False), 400
    session.clear()
    flash("Your password was reset. Please log in with your new password.", "success")
    return redirect(url_for("login_page"))


@app.get("/account")
def account_page():
    user = get_logged_in_user()
    if user is None:
        return redirect(url_for("login_page"))
    return render_auth_template("account.html", user=user)


@app.post("/logout")
def logout():
    if not valid_csrf_token():
        return csrf_error_response()
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login_page"))


@app.post("/create-checkout-session")
def create_checkout_session():
    product_id = request.form.get("product_id", "")
    product = PRODUCTS.get(product_id)
    if product is None:
        abort(400, description="Choose a valid product before starting checkout.")

    secret_key = stripe_secret_key()
    if not secret_key:
        return render_template(
            "checkout_message.html",
            title="Checkout is not configured",
            message="Card checkout is unavailable until the server is configured with a Stripe secret key.",
            action_url=url_for("products_page"),
            action_label="Back to products",
        ), 503

    try:
        stripe.api_key = secret_key
        checkout_session = stripe.checkout.Session.create(
            mode="payment",
            customer_creation="always",
            line_items=[
                {
                    "price_data": {
                        "currency": product["currency"],
                        "unit_amount": product["price_cents"],
                        "product_data": {
                            "name": product["name"],
                            "description": product["description"],
                        },
                    },
                    "quantity": 1,
                }
            ],
            success_url=url_for("checkout_success", _external=True)
            + "?session_id={CHECKOUT_SESSION_ID}",
            cancel_url=url_for("checkout_cancelled", _external=True),
        )
    except stripe.StripeError:
        app.logger.exception("Stripe Checkout session creation failed.")
        return render_template(
            "checkout_message.html",
            title="Checkout could not start",
            message="Stripe could not start a secure checkout. Please try again later.",
            action_url=url_for("products_page"),
            action_label="Back to products",
        ), 502

    if not checkout_session.url:
        app.logger.error("Stripe returned a Checkout session without a redirect URL.")
        return render_template(
            "checkout_message.html",
            title="Checkout could not start",
            message="Stripe did not return a secure checkout link. Please try again later.",
            action_url=url_for("products_page"),
            action_label="Back to products",
        ), 502

    return redirect(checkout_session.url, code=303)


@app.get("/checkout/success")
def checkout_success():
    session_id = request.args.get("session_id", "").strip()
    if not session_id:
        abort(400, description="A Stripe Checkout session ID is required.")

    secret_key = stripe_secret_key()
    if not secret_key:
        return render_template(
            "checkout_message.html",
            title="Payment status unavailable",
            message="The server is not configured to verify this payment. Contact FITTRACK before placing another order.",
            action_url=url_for("products_page"),
            action_label="Back to products",
        ), 503

    try:
        stripe.api_key = secret_key
        checkout_session = stripe.checkout.Session.retrieve(session_id)
    except stripe.StripeError:
        app.logger.exception("Stripe Checkout payment verification failed.")
        return render_template(
            "checkout_message.html",
            title="Payment status unavailable",
            message="We could not verify this payment with Stripe. Please contact FITTRACK before placing another order.",
            action_url=url_for("products_page"),
            action_label="Back to products",
        ), 502

    if checkout_session.status != "complete" or checkout_session.payment_status != "paid":
        return render_template(
            "checkout_message.html",
            title="Payment not confirmed",
            message="Stripe has not confirmed this payment yet. Please contact FITTRACK if you believe this is an error.",
            action_url=url_for("products_page"),
            action_label="Back to products",
        ), 202

    return render_template(
        "checkout_message.html",
        title="Payment complete",
        message="Your payment was confirmed by Stripe. Thank you for shopping with FITTRACK.",
        action_url=url_for("products_page"),
        action_label="Continue shopping",
    )


@app.get("/checkout/cancelled")
def checkout_cancelled():
    return render_template(
        "checkout_message.html",
        title="Checkout cancelled",
        message="No payment was completed. Return to the products page if you want to try again.",
        action_url=url_for("products_page"),
        action_label="Back to products",
    )


@app.get("/products.html")
def products_page():
    return send_from_directory(ROOT_DIR, "products.html")


@app.get("/<path:filename>")
def static_page(filename):
    if any(part.lower() == "templates" for part in Path(filename).parts):
        abort(404)
    if Path(filename).suffix.lower() not in ALLOWED_STATIC_SUFFIXES:
        abort(404)
    return send_from_directory(ROOT_DIR, filename)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
