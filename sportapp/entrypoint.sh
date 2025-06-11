#!/bin/bash
set -e  # Выход при ошибке

apply_migrations() {
    echo "Проверка миграций..."
    
    # Проверяем есть ли неприменённые миграции
    if python manage.py showmigrations | grep -q '\[ \]'; then
        echo "Найдены неприменённые миграции..."
        
        # Пытаемся применить миграции с обработкой ошибок
        if ! python manage.py migrate --verbosity=2; then
            echo "Миграция не удалась. Попытка исправить конфликты последовательностей..."
            
            # Исправляем конфликты последовательностей путём их сброса
            python manage.py shell -c "
import django.db
from django.core.management.color import no_style
from django.db import connection

with connection.cursor() as cursor:
    # Получаем все последовательности которые могут конфликтовать
    cursor.execute(\"\"\"
        SELECT sequence_name FROM information_schema.sequences 
        WHERE sequence_schema = 'public' 
        AND sequence_name LIKE '%_id_seq'
    \"\"\")
    sequences = cursor.fetchall()
    
    for seq in sequences:
        seq_name = seq[0]
        try:
            # Пытаемся удалить и пересоздать проблемные последовательности
            cursor.execute(f'DROP SEQUENCE IF EXISTS {seq_name} CASCADE')
            print(f'Удалена последовательность: {seq_name}')
        except Exception as e:
            print(f'Не удалось удалить последовательность {seq_name}: {e}')
"
            
            # Повторная попытка миграции после очистки последовательностей
            echo "Повторная попытка миграций после очистки последовательностей..."
            python manage.py migrate --fake-initial
        fi
        
        # Применяем миграции django_celery_beat отдельно
        echo "Применение миграций django_celery_beat..."
        python manage.py migrate django_celery_beat
    else
        echo "Все миграции уже применены."
    fi
}

create_superuser() {
    if [ -z "$DJANGO_SUPERUSER_EMAIL" ]; then
        echo "DJANGO_SUPERUSER_EMAIL не задан. Пропускаем создание суперпользователя."
        return
    fi

    echo "Проверка наличия суперпользователя..."
    if ! python manage.py shell -c "
from django.contrib.auth import get_user_model
User = get_user_model()
print(User.objects.filter(email='$DJANGO_SUPERUSER_EMAIL').exists())
" | grep -q "True"; then
        echo "Создание суперпользователя..."
        python manage.py shell -c "
from django.contrib.auth import get_user_model
User = get_user_model()
User.objects.create_superuser(
    username='$DJANGO_SUPERUSER_USERNAME',
    email='$DJANGO_SUPERUSER_EMAIL',
    password='${DJANGO_SUPERUSER_PASSWORD:-admin123}',
    fullname='${DJANGO_SUPERUSER_FULLNAME:-Admin}'
)
"
    else
        echo "Суперпользователь уже существует."
    fi
}

case "$1" in
    django)
        apply_migrations
        create_superuser
        echo "Запуск Django сервера..."
        exec python manage.py runserver 0.0.0.0:8000
        ;;
    celery_worker)
        apply_migrations
        echo "Запуск Celery worker..."
        exec celery -A celeryconfig.app:celery_app worker -l INFO
        ;;
    celery_beat)
        apply_migrations
        echo "Запуск Celery beat..."
        exec celery -A celeryconfig.app:celery_app beat -l INFO --scheduler django_celery_beat.schedulers:DatabaseScheduler
        ;;
    *)
        echo "Использование: $0 {django|celery_worker|celery_beat}"
        exit 1
        ;;
esac