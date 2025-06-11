from django.contrib import admin
from .models import Users, Events, Organizers


@admin.register(Users)
class UsersAdmin(admin.ModelAdmin):
    list_display = ("username", "fullname", "email", "role", "is_superuser")


@admin.register(Organizers)
class OrganizersAdmin(admin.ModelAdmin):
    list_display = ("orgName", "orgEmail", "user")


@admin.register(Events)
class EventsAdmin(admin.ModelAdmin):
    list_display = ("name", "status", "startDate", "organizer")
    list_filter = ("status",)
    actions = ["approve_events", "delete_pending_events"]

    @admin.action(description="✅ Одобрить выбранные события (сделать 'Запланировано')")
    def approve_events(self, request, queryset):
        updated = queryset.filter(status="Проверка").update(status="Запланировано")
        self.message_user(request, f"Одобрено {updated} событие(й).")

    @admin.action(description="❌ Удалить события со статусом 'Проверка'")
    def delete_pending_events(self, request, queryset):
        to_delete = queryset.filter(status="Проверка")
        count = to_delete.count()
        to_delete.delete()
        self.message_user(request, f"Удалено {count} событие(й) со статусом 'Проверка'.")
