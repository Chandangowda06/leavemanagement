from twilio.rest import Client

def send_msg(to, msg):
    account_sid = 'ACaeb8db70f48c1d83c607b636c40cee87'
    auth_token = 'a00546177cd9a89f6741abb95fe2a264'

    client = Client(account_sid, auth_token)

    message = client.messages.create(
        to='+91'+to,  # Recipient's phone number
        from_='+16562184606',  # Your Twilio phone number (must be purchased or verified in your Twilio account)
        body=msg  # Message content
    )

    print(f"Message SID: {message.sid}")

