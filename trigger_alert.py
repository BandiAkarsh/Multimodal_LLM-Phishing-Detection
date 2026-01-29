import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_live_phish_test():
    sender_email = "akarshbandi82@gmail.com"
    receiver_email = "akarshbandi82@gmail.com"
    password = "qrxntgtupgniomks" # User's App Password

    message = MIMEMultipart("alternative")
    message["Subject"] = "🚨 ACTION REQUIRED: Your account has been limited"
    message["From"] = f"PayPal Security <{sender_email}>"
    message["To"] = receiver_email

    # High-confidence phishing template
    html = """
    <html>
      <body style="font-family: sans-serif;">
        <div style="padding: 20px; border: 1px solid #eee; border-radius: 10px; max-width: 500px;">
            <h2 style="color: #0070ba;">PayPal</h2>
            <hr>
            <p>Hello,</p>
            <p>We've noticed some unusual activity on your account. For your protection, we've temporarily limited your ability to send or receive funds.</p>
            <p>To restore full access, please verify your information:</p>
            <p style="text-align: center;">
                <a href="http://paypa1-secure-verification.com/login" 
                   style="background: #0070ba; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
                   Confirm My Identity
                </a>
            </p>
            <p style="font-size: 10px; color: #999;">This is a test email sent by the Phishing Guard System.</p>
        </div>
      </body>
    </html>
    """

    message.attach(MIMEText(html, "html"))

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, message.as_string())
        print("Live phishing test email sent!")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    send_live_phish_test()
