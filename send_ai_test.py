import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_ai_test():
    sender_email = "akarshbandi82@gmail.com"
    receiver_email = "akarshbandi82@gmail.com"
    password = "qrxntgtupgniomks" # User's App Password

    message = MIMEMultipart("alternative")
    message["Subject"] = "🤖 Notification: New Document Shared with You"
    message["From"] = sender_email
    message["To"] = receiver_email

    # Triggering AI_GENERATED_PHISHING logic
    html = """
    <html>
      <body>
        <p>Hello valued customer,<br><br>
           We hope this email finds you well. A new secure document has been shared with you on our cloud platform. 
           Please proceed to the following link to review and sign the agreement at your earliest convenience.<br><br>
           <a href="http://gpt-crafted-phish.net/view/docs"><b>Open Secure Document</b></a><br><br>
           Thank you for your continued partnership.
        </p>
      </body>
    </html>
    """
    message.attach(MIMEText(html, "html"))

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, message.as_string())
        print("AI-Generated test email sent!")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    send_ai_test()
