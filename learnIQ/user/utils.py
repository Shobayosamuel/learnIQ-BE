import secrets
from django.conf import settings
from django.core.mail import send_mail
from datetime import timedelta
from django.utils import timezone
from django.core.signing import TimestampSigner, BadSignature
from django.contrib.auth import get_user_model

from .models import OTP

FROM_EMAIL = settings.EMAIL_HOST_USER

def generate_otp() -> str:
    """Generate a random 6 digit OTP"""
    return "".join(f"{secrets.randbelow(10)}" for _ in range(6))

def generate_email_token(email) -> str:
    """Generate token for email"""
    signer = TimestampSigner()
    token = signer.sign(email)
    return token

def unscramble_email_token(token) -> str:
    """Get email from token"""
    signer = TimestampSigner()
    try:
        email = signer.unsign(token, max_age=1000)
    except BadSignature as e:
        return f"Error: {str(e)}"
    return email

def add_otp_to_user(email: str) -> None:
    """Add otp to user"""
    otp = generate_otp()
    expiry_date = timezone.now() + timedelta(minutes=10)
    User = get_user_model()
    # Delete user OTP record if OTP exist for user
    if User.objects.get(email=email):
        otp_list = OTP.objects.filter(email=email)
        if otp_list.exists():
            otp_list.delete()
        OTP.objects.create(email=email, otp=otp, expires_at=expiry_date)
    return otp
        
def send_password_reset_mail(email: str) -> None:
    """Send OTP to user"""
    otp = add_otp_to_user(email)
    subject = "Password Reset OTP"
    message = f"Your otp for password reset is: {otp}. The token is only valid for 10 minutes."
    send_mail(subject=subject, message=message, from_email=FROM_EMAIL, recipient_list=[email], fail_silently=False)
