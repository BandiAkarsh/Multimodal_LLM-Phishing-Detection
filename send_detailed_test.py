import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_detailed_test():
    sender_email = "akarshbandi82@gmail.com"
    receiver_email = "akarshbandi82@gmail.com"
    password = "qrxntgtupgniomks" # User's App Password

    message = MIMEMultipart("alternative")
    message["Subject"] = "🚨 Action Required: Verify your Gophish Campaign"
    message["From"] = sender_email
    message["To"] = receiver_email

    # Including ?rid= to trigger PHISHING_KIT detection
    html = """
    <html>
      <body>
        <p>Dear Admin,<br><br>
           Please review your latest campaign stats here:<br><br>
           <a href="http://example-phish-kit.com/login?rid=pk_test_99"><b>View Dashboard</b></a><br><br>
        </p>
      </body>
    </html>
    """
    message.attach(MIMEText(html, "html"))

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, message.as_string())
        print("Detailed test email sent!")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    send_detailed_test()
