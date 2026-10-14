import hashlib
import os
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch

import mongomock

import app as fittrack


class FittrackBackendTests(unittest.TestCase):
    def setUp(self):
        self.mongo_client = mongomock.MongoClient()
        fittrack.app.config.update(
            TESTING=True,
            SECRET_KEY="test-session-key",
            MONGO_CLIENT=self.mongo_client,
            MONGO_DB_NAME="fittrack_test",
        )
        fittrack.app.extensions.pop("fittrack_mongo_indexes_key", None)
        self.db = self.mongo_client["fittrack_test"]
        self.client = fittrack.app.test_client()

    def tearDown(self):
        self.mongo_client.close()

    def create_csrf_token(self):
        response = self.client.get("/signup.html")
        self.assertEqual(response.status_code, 200)
        with self.client.session_transaction() as session:
            return session["csrf_token"]

    def signup(self, *, email="member@example.com", phone="+15551234567"):
        csrf = self.create_csrf_token()
        return self.client.post(
            "/signup.html",
            data={
                "csrf_token": csrf,
                "first_name": "Taylor",
                "last_name": "Member",
                "email": email,
                "phone": phone,
                "password": "Correct-Horse-42!",
                "goal": "Build muscle",
            },
        )

    def test_configured_mongodb_uri_is_well_formed(self):
        uri = fittrack.app.config["MONGO_URI"]

        # Guards against placeholder-style URIs such as
        # mongodb+srv://user:<password>@host/ where angle brackets leak
        # into the credentials and make authentication fail.
        self.assertTrue(uri.startswith(("mongodb://", "mongodb+srv://")))
        self.assertNotIn("<", uri)
        self.assertNotIn(">", uri)
        self.assertIn("://", uri)
        _, remainder = uri.split("://", 1)
        self.assertIn("@", remainder)
        userinfo, host = remainder.rsplit("@", 1)
        username, _, password = userinfo.partition(":")
        self.assertTrue(username, "MongoDB URI must include a username")
        self.assertTrue(password, "MongoDB URI must include a password")
        self.assertTrue(host.split("/")[0], "MongoDB URI must include a host")

    def test_product_api_returns_server_catalog_and_prices(self):
        response = self.client.get("/api/products")

        self.assertEqual(response.status_code, 200)
        products = response.get_json()
        self.assertEqual([product["id"] for product in products], list(fittrack.PRODUCTS))
        self.assertEqual(
            [product["price_cents"] for product in products],
            [3900, 2800, 4200],
        )

    def test_invalid_product_is_rejected_before_stripe(self):
        with patch.object(fittrack.stripe.checkout.Session, "create") as create_session:
            response = self.client.post(
                "/create-checkout-session",
                data={"product_id": "unknown"},
            )

        self.assertEqual(response.status_code, 400)
        create_session.assert_not_called()

    def test_backend_files_are_not_served_as_static_content(self):
        self.assertEqual(self.client.get("/app.py").status_code, 404)
        self.assertEqual(
            self.client.get("/templates/checkout_message.html").status_code,
            404,
        )

    def test_checkout_requires_secret_key(self):
        with patch.dict(os.environ, {"STRIPE_SECRET_KEY": ""}):
            response = self.client.post(
                "/create-checkout-session",
                data={"product_id": "lean-protein"},
            )

        self.assertEqual(response.status_code, 503)
        self.assertIn(b"Checkout is not configured", response.data)

    def test_signup_stores_contact_and_signs_in(self):
        response = self.signup()

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "/account")
        account = self.client.get("/account")
        self.assertEqual(account.status_code, 200)
        self.assertIn(b"+15551234567", account.data)
        user = self.db.users.find_one({"email": "member@example.com"})
        self.assertNotEqual(user["password_hash"], "Correct-Horse-42!")

    def test_signup_rejects_short_password_and_duplicate_contact(self):
        csrf = self.create_csrf_token()
        response = self.client.post(
            "/signup.html",
            data={
                "csrf_token": csrf,
                "first_name": "Taylor",
                "last_name": "Member",
                "email": "member@example.com",
                "phone": "+15551234567",
                "password": "short",
                "goal": "Build muscle",
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"at least 12 characters", response.data)

        self.assertEqual(self.signup().status_code, 302)
        with self.client.session_transaction() as session:
            session.clear()
        duplicate = self.signup(email="different@example.com")
        self.assertEqual(duplicate.status_code, 400)
        self.assertIn(b"already uses", duplicate.data)

        duplicate_email = self.signup(
            email="MEMBER@example.com",
            phone="+15551234568",
        )
        self.assertEqual(duplicate_email.status_code, 400)
        self.assertIn(b"already uses", duplicate_email.data)

    def test_signup_rejects_missing_csrf_token(self):
        response = self.client.post(
            "/signup.html",
            data={
                "first_name": "Taylor",
                "last_name": "Member",
                "email": "member@example.com",
                "phone": "+15551234567",
                "password": "Correct-Horse-42!",
                "goal": "Build muscle",
            },
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn(b"Form expired", response.data)

    def test_login_accepts_email_or_phone(self):
        self.assertEqual(self.signup().status_code, 302)
        with self.client.session_transaction() as session:
            session.clear()

        for identifier in ("member@example.com", "+1 (555) 123-4567"):
            csrf = self.create_csrf_token()
            response = self.client.post(
                "/login.html",
                data={
                    "csrf_token": csrf,
                    "identifier": identifier,
                    "password": "Correct-Horse-42!",
                },
            )
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.location, "/account")
            self.assertEqual(self.client.get("/account").status_code, 200)
            with self.client.session_transaction() as session:
                session.clear()

    def test_login_rejects_wrong_password(self):
        self.assertEqual(self.signup().status_code, 302)
        with self.client.session_transaction() as session:
            session.clear()
        csrf = self.create_csrf_token()

        response = self.client.post(
            "/login.html",
            data={
                "csrf_token": csrf,
                "identifier": "member@example.com",
                "password": "incorrect-password",
            },
        )

        self.assertEqual(response.status_code, 401)
        self.assertIn(b"incorrect", response.data)

    def test_forgot_password_sends_reset_link_without_disclosing_account(self):
        self.assertEqual(self.signup().status_code, 302)
        with self.client.session_transaction() as session:
            session.clear()
        csrf = self.create_csrf_token()
        settings = {
            "SMTP_HOST": "smtp.example.test",
            "SMTP_FROM": "FITTRACK <accounts@example.test>",
            "PUBLIC_BASE_URL": "https://fittrack.example.test",
            "SMTP_PORT": "587",
            "SMTP_USERNAME": "",
            "SMTP_PASSWORD": "",
        }
        with patch.object(fittrack, "password_reset_email_settings", return_value=settings):
            with patch.object(fittrack, "send_password_reset_email") as send_email:
                response = self.client.post(
                    "/forgot-password",
                    data={"csrf_token": csrf, "email": "member@example.com"},
                )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"a password reset link will arrive", response.data)
        reset_url = send_email.call_args.args[1]
        token = reset_url.rsplit("/", 1)[1]
        self.assertTrue(token)

    def test_forgot_password_response_does_not_disclose_unknown_email(self):
        csrf = self.create_csrf_token()
        with patch.object(fittrack, "password_reset_email_settings", return_value=None):
            response = self.client.post(
                "/forgot-password",
                data={"csrf_token": csrf, "email": "unknown@example.com"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"a password reset link will arrive", response.data)

    def test_password_reset_is_one_time_and_invalidates_existing_sessions(self):
        self.assertEqual(self.signup().status_code, 302)
        user = self.db.users.find_one({"email": "member@example.com"})
        now = datetime.now(timezone.utc)
        self.db.users.update_one(
            {"_id": user["_id"]},
            {
                "$set": {
                    "password_reset": {
                        "token_hash": hashlib.sha256(b"reset-token").hexdigest(),
                        "expires_at": now + timedelta(minutes=30),
                        "created_at": now,
                    }
                }
            },
        )

        csrf = self.create_csrf_token()
        response = self.client.post(
            "/reset-password/reset-token",
            data={
                "csrf_token": csrf,
                "password": "New-Password-42!",
                "confirm_password": "New-Password-42!",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "/login.html")
        self.assertEqual(self.client.get("/account").status_code, 302)

        invalidated = self.client.post(
            "/reset-password/reset-token",
            data={
                "csrf_token": self.create_csrf_token(),
                "password": "Another-Password-42!",
                "confirm_password": "Another-Password-42!",
            },
        )
        self.assertEqual(invalidated.status_code, 400)

        csrf = self.create_csrf_token()
        login = self.client.post(
            "/login.html",
            data={
                "csrf_token": csrf,
                "identifier": "+15551234567",
                "password": "New-Password-42!",
            },
        )
        self.assertEqual(login.status_code, 302)
        self.assertEqual(login.location, "/account")

    def test_checkout_uses_server_price_and_redirects_to_stripe(self):
        with patch.dict(os.environ, {"STRIPE_SECRET_KEY": "sk_test_unit_test"}):
            with patch.object(
                fittrack.stripe.checkout.Session,
                "create",
                return_value=Mock(url="https://checkout.stripe.test/session"),
            ) as create_session:
                response = self.client.post(
                    "/create-checkout-session",
                    data={"product_id": "lean-protein"},
                )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.location, "https://checkout.stripe.test/session")
        line_item = create_session.call_args.kwargs["line_items"][0]
        self.assertEqual(line_item["price_data"]["unit_amount"], 3900)
        self.assertEqual(line_item["price_data"]["product_data"]["name"], "Lean Protein")

    def test_success_page_only_confirms_paid_sessions(self):
        paid_session = Mock(status="complete", payment_status="paid")
        with patch.dict(os.environ, {"STRIPE_SECRET_KEY": "sk_test_unit_test"}):
            with patch.object(
                fittrack.stripe.checkout.Session,
                "retrieve",
                return_value=paid_session,
            ):
                response = self.client.get("/checkout/success?session_id=cs_test_paid")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Payment complete", response.data)

    def test_success_page_does_not_confirm_unpaid_sessions(self):
        unpaid_session = Mock(status="complete", payment_status="unpaid")
        with patch.dict(os.environ, {"STRIPE_SECRET_KEY": "sk_test_unit_test"}):
            with patch.object(
                fittrack.stripe.checkout.Session,
                "retrieve",
                return_value=unpaid_session,
            ):
                response = self.client.get("/checkout/success?session_id=cs_test_unpaid")

        self.assertEqual(response.status_code, 202)
        self.assertIn(b"Payment not confirmed", response.data)


if __name__ == "__main__":
    unittest.main()
