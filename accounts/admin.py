from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser, UserProfile

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser


# Customizing the UserAdmin for CustomUser
class CustomUserAdmin(UserAdmin):
    model = CustomUser

    # Define the fields to be displayed in the User admin page
    list_display = (
        "email",
        "is_active",
        "is_staff",
        "is_superuser",
        "email_verified",
        "date_joined",
    )

    ordering = ("-date_joined",)

    # Fields to be editable in the admin page
    list_editable = ("is_active", "email_verified")

    # Add search functionality to search by email
    search_fields = ("email",)

    # Filter by active status, staff status, and verified email
    list_filter = ("is_active", "is_staff", "is_superuser", "email_verified")

    # The fields shown in the form when adding/editing a user
    fieldsets = (
        (None, {"fields": ("email", "password")}),
        ("Personal Info", {"fields": ("bio", "profile_picture")}),
        (
            "Permissions",
            {"fields": ("is_active", "is_staff", "is_superuser", "email_verified")},
        ),
        ("Important Dates", {"fields": ("date_joined",)}),
    )
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": ("email", "password1", "password2"),
            },
        ),
    )

    # Make the 'CustomUser' model the default user model for the admin page
    add_form_template = "admin/auth/user/add_form.html"


class UserProfileAdmin(admin.ModelAdmin):
    # Define the fields to be displayed in the UserProfile admin page
    list_display = ("user", "first_name", "last_name", "bio", "profile_picture")

    # Add search functionality by user email or name
    search_fields = ("user__email", "first_name", "last_name")

    # Add filter by profile picture availability
    list_filter = ("profile_picture",)

    # Allow editing of the fields from the list view
    list_editable = ("bio",)

    # Fields shown in the form when adding/editing a user profile
    fieldsets = (
        (
            None,
            {"fields": ("user", "first_name", "last_name", "bio", "profile_picture")},
        ),
    )

    # Make sure 'user' is not editable, as it is linked with CustomUser
    readonly_fields = ("user",)


# Register the CustomUser and UserProfile models with their respective admin classes
admin.site.register(CustomUser, CustomUserAdmin)
admin.site.register(UserProfile, UserProfileAdmin)
