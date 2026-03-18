from fastapi_mail import FastMail, MessageSchema, ConnectionConfig, MessageType
from app.core.config import settings

mail_config = ConnectionConfig(
    MAIL_USERNAME=settings.MAIL_USERNAME,
    MAIL_PASSWORD=settings.MAIL_PASSWORD,
    MAIL_FROM=settings.MAIL_FROM,
    MAIL_PORT=settings.MAIL_PORT,
    MAIL_SERVER=settings.MAIL_SERVER,
    MAIL_STARTTLS=settings.MAIL_STARTTLS,
    MAIL_SSL_TLS=settings.MAIL_SSL_TLS,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=True,
)

fast_mail = FastMail(mail_config)


async def send_password_reset_email(email: str, reset_token: str) -> None:
    """
    Sends a password reset link to the user's email via Mailtrap SMTP.
    In development, Mailtrap catches this — no real email is delivered.
    In production, swap MAIL_SERVER/credentials for SendGrid or AWS SES.
    """
    reset_url = f"http://localhost:8000/auth/password-reset/confirm?token={reset_token}"

    html_body = f"""
    <html>
      <body>
        <h2>Password Reset Request</h2>
        <p>You requested a password reset for your IoT Security Suite account.</p>
        <p>Click the link below to reset your password. This link expires in
           {settings.RESET_TOKEN_EXPIRE_MINUTES} minutes.</p>
        <p><a href="{reset_url}">Reset My Password</a></p>
        <p>If you did not request this, ignore this email — your password will not change.</p>
        <hr>
        <small>IoT Backend Security Suite — Development Environment</small>
      </body>
    </html>
    """

    message = MessageSchema(
        subject="Password Reset Request",
        recipients=[email],
        body=html_body,
        subtype=MessageType.html,
    )

    await fast_mail.send_message(message)