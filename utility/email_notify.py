from archerysettings.models import email_db
from django.conf import settings
from django.core.mail import send_mail


def email_sch_notify(subject, message):
    to_mail = ''
    all_email = email_db.objects.all()
    for email in all_email:
        to_mail = email.recipient_list

    print(to_mail)
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [to_mail]
    try:
        send_mail(subject, message, email_from, recipient_list)
    except Exception as e:
        print(e)
