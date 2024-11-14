# 1. Standard library imports
import logging

# 2. Django imports
from django.conf import settings
from django.core.mail import EmailMessage
from django.template.loader import render_to_string


logger = logging.getLogger("__name__")


def send_email(subject, body, context, recipient_list, is_body_template=True):
    """
    Renders an e-mail to `email` and sends it to the provided recipient list.

    :param subject: Subject line of the email
    :param body: Path to the template (if is_body_template=True) or the raw body (if is_body_template=False)
    :param context: Context for the email template (if is_body_template=True)
    :param recipient_list: List of email addresses to send the email to
    :param is_body_template: If True, body is considered as a template, otherwise it's a raw string
    """
    try:
        if settings.EMAIL_NOTIFY:
            if is_body_template:
                # Render the email body using the provided template and context
                body = render_to_string(body, context).strip()

            # Create the email message
            msg = EmailMessage(
                subject=settings.ACCOUNT_EMAIL_SUBJECT_PREFIX + subject.title(),
                body=body,
                from_email=settings.DEFAULT_FROM_EMAIL,
                bcc=recipient_list,  # To send the email to multiple recipients
            )
            msg.content_subtype = "html"  # Ensure the email body is sent as HTML
            msg.send()
            logger.info(f"Email sent to {recipient_list}")
        else:
            logger.warning("EMAIL_NOTIFY setting is off. No email sent.")
    except Exception as e:
        logger.error(f"Error sending email to {recipient_list}: {str(e)}")
