
import os
from celery import Celery
from celery.schedules import crontab
from . import tasks

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'backend.settings')

celery_app = Celery('sportapp')
celery_app.config_from_object('django.conf:settings', namespace='CELERY')
celery_app.autodiscover_tasks()

from celery.schedules import crontab

celery_app.conf.beat_schedule = {
    'update-event-statuses-every-minute': {
        'task': 'celeryconfig.tasks.update_event_statuses',
        'schedule': crontab(minute='*'),  # каждую минуту
    },
}

