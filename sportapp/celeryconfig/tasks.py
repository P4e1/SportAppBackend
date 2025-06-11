from celery import shared_task
from django.utils import timezone
from datetime import datetime, timedelta

@shared_task
def update_event_statuses():
    from sportapp.models import Events  # локальный импорт

    now = timezone.localtime(timezone.now())
    today = now.date()
    current_time = now.time()
    now_dt = datetime.combine(today, current_time)
    updated = 0

    for event in Events.objects.all():
        start_dt = datetime.combine(event.startDate, event.startTime)
        end_dt = datetime.combine(event.endDate, event.endTime)

        if event.status == "Запланировано" and start_dt - timedelta(days=3) <= now_dt:
            event.status = "Регистрация открыта"
            event.save()
            updated += 1
        elif event.status == "Регистрация открыта" and now_dt >= start_dt:
            event.status = "Регистрация закрыта"
            event.save()
            updated += 1
        elif event.status == "Регистрация закрыта" and start_dt <= now_dt <= end_dt:
            event.status = "Идёт"
            event.save()
            updated += 1

    return f"Updated {updated} events"
