# 1. Django imports
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

# 2. Local imports
from .models import CustomUser, Student, Instructor


class CustomUserAdmin(UserAdmin):
    model = CustomUser
    list_display = (
        "email",
        "first_name",
        "last_name",
        "date_joined",
        "is_active",
        "is_staff",
        "is_student",
        "is_instructor",
    )
    list_filter = ("is_active", "is_staff", "is_student", "is_instructor")
    search_fields = ("email", "first_name", "last_name")
    ordering = ("email",)

    fieldsets = (
        (None, {"fields": ("email", "password")}),
        (
            "Personal Information",
            {"fields": ("first_name", "last_name", "bio", "picture")},
        ),
        (
            "Permissions",
            {
                "fields": (
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "is_student",
                    "is_instructor",
                )
            },
        ),
        ("Important Dates", {"fields": ("date_joined",)}),
    )

    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": (
                    "email",
                    "password1",
                    "password2",
                    "is_student",
                    "is_instructor",
                ),
            },
        ),
    )
    filter_horizontal = ()


class StudentAdmin(admin.ModelAdmin):
    list_display = ("user", "interests", "skill_level")
    search_fields = ("user__email", "user__first_name", "user__last_name")
    list_filter = ("skill_level",)
    ordering = ("user__email",)


class InstructorAdmin(admin.ModelAdmin):
    list_display = (
        "user",
        "expertise_area",
        "years_of_experience",
        "is_verified",
        "verified_at",
    )
    search_fields = (
        "user__email",
        "user__first_name",
        "user__last_name",
        "expertise_area",
    )
    list_filter = ("is_verified", "years_of_experience")
    ordering = ("user__email",)


admin.site.register(CustomUser, CustomUserAdmin)
admin.site.register(Student, StudentAdmin)
admin.site.register(Instructor, InstructorAdmin)
