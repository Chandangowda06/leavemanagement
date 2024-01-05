from smtplib import SMTPException
import smtplib
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.core.mail import send_mail
from leavemanagement import settings
from user_app.models import User
from django.template.loader import get_template
from weasyprint import HTML
from django.core.files.storage import default_storage

def generate_pdf(context, name):
    
    # Get your HTML template
    template = get_template('leave-pdf.html')
    
    # Render the template with the desired context
    html_string = template.render(context)

    # Create a WeasyPrint HTML object
    html = HTML(string=html_string)

    document = html.render()

    # Get the size of the rendered document
    content_width, content_height = document.pages[0].width, document.pages[0].height

    # Set the page size based on the content size
    page_size = (content_width, content_height)

    # Generate a PDF from the HTML with dynamically sized pages
    pdf_bytes = document.write_pdf(target=None, zoom=1, pages_sizes=[page_size])

    # Create a Django HttpResponse with the PDF content
    file_path = f'letters/{name}.pdf'
    with default_storage.open(file_path, 'wb') as pdf_file:
        pdf_file.write(pdf_bytes)
    print("complete PDF")
    return file_path




def generate_password_reset_token(user):
    try:
        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        return uidb64, token
    except Exception as e:
        print(e)

def send_password_reset_email(user, request):
    try:
        uidb64, token = generate_password_reset_token(user)
        domain = request.headers.get('Origin')
        reset_url =  f"{domain}/password_reset/confirm/{uidb64}/{token}/"
        message = f"Click the link to reset your password: {reset_url}"
        send_email('Password reset request', message, user.email)
    except Exception as e:
        print(e)


def extract_user_from_token(uidb64, token):
    try:
        user_id = force_bytes(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=user_id)
        if default_token_generator.check_token(user, token):
            return user
    except (ValueError, User.DoesNotExist):
        pass
    return None

def send_email(sub, msg, to):
    try:
        send_mail(
        subject=sub,
        message=msg,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list = [to],
        fail_silently=False,
        )
    except (SMTPException, smtplib.SMTPException) as e:
        raise("Error in sending email")

