from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser, StudentResult


class CustomUserAdmin(UserAdmin):
    # Define the fields to display in the admin list view
    list_display = ('username', 'email', 'full_name', 'bio', 'is_staff', 'is_active')
    ordering = ('username',)

    # Define fieldsets for editing a user in the admin detail view
    fieldsets = (
        (None, {'fields': ('username', 'password')}),  # Basic user info
        ('Personal info', {
            'fields': (
                'full_name', 'email', 'user_class', 'roll_no', 'stream',
                'dob', 'college_name', 'contact_number', 'bio', 'links'
            )
        }),
        ('Permissions', {
            'fields': ('is_staff', 'is_active', 'groups', 'user_permissions')
        }),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )

    # Fields to show when creating a new user
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'full_name', 'password1', 'password2', 'bio'),
        }),
    )


@admin.register(StudentResult)
class StudentResultAdmin(admin.ModelAdmin):
    # Fields to display in the list view
    list_display = ('roll_no', 'name', 'performance', 'mcqs','practical_no' ,'attendance', 'batch', 'total')
    
    # Enable search functionality
    search_fields = ('roll_no', 'name', 'batch')

    # Filters for the list view
    list_filter = ('batch', 'performance')

    # Ordering of records
    ordering = ('roll_no',)

    # Read-only fields (optional)
    readonly_fields = ('total',)

    # Fields to display in the detail view
    fieldsets = (
        (None, {
            'fields': ('roll_no', 'name', 'batch')
        }),
        ('Performance Details', {
            'fields': ('performance', 'mcqs', 'attendance','practical_no',  'total')
        }),
    )


# Register the CustomUser model with the custom admin
admin.site.register(CustomUser, CustomUserAdmin)
