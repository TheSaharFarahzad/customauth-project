from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from .models import CustomUser, UserProfile

User = get_user_model()


# @receiver(post_save, sender=User)
# def create_student_profile(sender, instance, created, **kwargs):
#     if instance.is_student:
#         Student.objects.get_or_create(user=instance)


# @receiver(post_save, sender=User)
# def create_instructor_profile(sender, instance, created, **kwargs):
#     if instance.is_instructor:
#         Instructor.objects.get_or_create(user=instance)


@receiver(post_save, sender=CustomUser)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)


@receiver(post_save, sender=CustomUser)
def save_user_profile(sender, instance, **kwargs):
    instance.profile.save()
