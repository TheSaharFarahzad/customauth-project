import pytest
from django.db.models.signals import post_save
from django.contrib.auth import get_user_model
from yourapp.signals import create_student_profile, create_instructor_profile
from yourapp.models import Student, Instructor
from tests.factories import UserFactory

pytestmark = pytest.mark.unit

User = get_user_model()


class TestProfileSignals:
    def test_create_student_profile_signal(self, mocker):
        """Test that the create_student_profile signal is called correctly."""
        instance = UserFactory(is_student=True)
        mock = mocker.patch("yourapp.signals.Student.objects.get_or_create")

        post_save.send(User, instance=instance, created=True)

        mock.assert_called_with(user=instance)

    def test_create_instructor_profile_signal(self, mocker):
        """Test that the create_instructor_profile signal is called correctly."""
        instance = UserFactory(is_instructor=True)
        mock = mocker.patch("yourapp.signals.Instructor.objects.get_or_create")

        post_save.send(User, instance=instance, created=True)

        mock.assert_called_with(user=instance)
