# FITTRACK GYM

FITTRACK GYM is a gym and fitness club website with information about the club, trainers, memberships, and fitness products. Its Flask backend provides account registration and login, password recovery, and Stripe test-mode checkout. User accounts and password-reset data are stored in MongoDB.

## Features

- Gym pages for the home, about, contact, admission, and trainers sections
- Product catalog with Stripe Checkout integration
- Account signup and login using email or phone number
- Email-based password reset
- MongoDB storage for user accounts and embedded one-time password-reset data

## Run the website and checkout backend

1. Install Python 3.10 or later.
2. Install the development dependencies (including test tools):

   ```powershell
   py -m venv .venv
   .venv\Scripts\Activate.ps1
   python -m pip install -r requirements-dev.txt
   ```

   By default, the app connects to the project's MongoDB Atlas cluster (`cluster1.j1tmeoi.mongodb.net`) and uses the `fittrack_gym` database, which is created automatically on first use. To use another MongoDB server, set the connection URI and (optionally) the database name in the same PowerShell session:

   ```powershell
   $env:MONGODB_URI = "mongodb+srv://<username>:<password>@<cluster-host>/"
   $env:MONGODB_DATABASE = "fittrack_gym"
   ```

   Set `MONGODB_URI` in the environment to override the built-in connection string so cluster credentials stay out of source code. This app starts with an empty MongoDB database; it does not import the former SQLite data.

3. Set a Stripe **test-mode** secret key in the same PowerShell session:

   ```powershell
   $env:STRIPE_SECRET_KEY = "sk_test_your_key"
   ```

   Do not put a Stripe secret key in HTML, JavaScript, or a committed file.

4. Set a stable random Flask session secret:

   ```powershell
   $env:FLASK_SECRET_KEY = "replace-with-a-long-random-secret"
   ```

5. Configure SMTP for password recovery. The app sends a one-time reset link to the email on the account:

   ```powershell
   $env:SMTP_HOST = "smtp.example.com"
   $env:SMTP_PORT = "587"
   $env:SMTP_USERNAME = "your-smtp-username"
   $env:SMTP_PASSWORD = "your-smtp-password"
   $env:SMTP_FROM = "FITTRACK GYM <accounts@example.com>"
   $env:PUBLIC_BASE_URL = "http://127.0.0.1:5000"
   ```

   Use your real HTTPS website URL for `PUBLIC_BASE_URL` in production. SMTP uses STARTTLS. Keep all secrets in environment variables, never in source code.

6. Start the website:

   ```powershell
   python app.py
   ```

7. Open `http://127.0.0.1:5000/`. Sign up with an email address and an international phone number; either one can be used with the password to log in. Password reset is sent to the account email. User documents are stored in MongoDB; each user's current password-reset token is embedded in that document and expires after 30 minutes.

If `FLASK_SECRET_KEY` is not set, the app generates a temporary secret for local development and login sessions will not survive a server restart. Configure the variable for normal use.

To run the backend tests, activate the virtual environment and run:

```powershell
python -m unittest
```

The checkout success page verifies the Stripe session before confirming payment. This starter backend does not yet handle shipping, inventory, refunds, or order fulfillment; add verified Stripe webhooks before automating those production workflows.
