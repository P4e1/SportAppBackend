from django.contrib.auth.models import AbstractUser
from django.db import models

class Users(AbstractUser):
    email = models.EmailField(unique=True)
    fullname = models.CharField(max_length=256)
    role = models.CharField(max_length=20, blank=True, null=True)
    phone = models.CharField(max_length=20, blank=True)

    REQUIRED_FIELDS = ['email', 'fullname']  # username остаётся основным полем

    def __str__(self):
        return self.fullname


class Organizers(models.Model):
    user = models.ForeignKey(Users, on_delete=models.SET_NULL, null=True)
    orgName = models.CharField(max_length=256)
    orgEmail = models.EmailField(null=True)
    orgPhone = models.CharField(max_length=20, blank=True, null=True)
    orgAddress = models.CharField(max_length=256, default="Unknown", null=False)


class Events(models.Model):
    organizer = models.ForeignKey(Organizers, on_delete=models.SET_NULL, null=True)
    name = models.CharField(max_length=256)
    description = models.CharField(max_length=256)
    typeOfCompetition = models.CharField(
        max_length=25,
        choices=[
            ('Индивидуальный', 'Индивидуальный'),
            ('Командный', 'Командный')
        ],
        null=True
    )
    startDate = models.DateField()
    startTime = models.TimeField()
    endDate = models.DateField()
    endTime = models.TimeField()
    status = models.CharField(
        max_length=100,
        choices=[
            ('Запланировано', 'Запланировано'),
            ('Регистрация открыта', 'Регистрация открыта'),
            ('Регистрация закрыта', 'Регистрация закрыта'),
            ('Идёт', 'Идёт'),
            ('Завершено', 'Завершено'),
            ('Проверка', 'Проверка')
        ]
    )
    address = models.CharField(max_length=256)
    aLotOfParticipant = models.IntegerField(default="0")
    limitOfParticipants = models.IntegerField()


class Institutions(models.Model):
    name = models.CharField(max_length=256)


class Participants(models.Model):
    user = models.ForeignKey(Users, on_delete=models.SET_NULL, null=True)
    institution = models.ForeignKey(Institutions, on_delete=models.SET_NULL, blank=True, null=True)
    dateR = models.DateField()
    height = models.IntegerField()
    weight = models.IntegerField()
    numberOfCompetitions = models.IntegerField(blank=True, null=True)
    rating = models.IntegerField(blank=True, null=True)


class Teams(models.Model):
    event = models.ForeignKey(Events, on_delete=models.SET_NULL, null=True)
    name = models.CharField(max_length=256)


class TeamsParticipants(models.Model):
    team = models.ForeignKey(Teams, on_delete=models.SET_NULL, null=True)
    participant = models.ForeignKey(Participants, on_delete=models.SET_NULL, null=True)
    status = models.CharField(
        max_length=100,
        choices=[
            ('Подтверждён', 'Подтверждён'),
            ('Отклонён', 'Отклонён'),
            ('Проверка', 'Проверка')
        ],
        default="Проверка"
    )
    place = models.IntegerField(blank=True, null=True)


class Notifications(models.Model):
    user = models.ForeignKey(Users, on_delete=models.SET_NULL, null=True)
    title = models.CharField(max_length=256)
    message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    isRead = models.BooleanField(default=False)
    type = models.CharField(
        max_length=16,
        choices=[
            ('info', 'info'),
            ('success', 'success'),
            ('warning', 'warning'),
            ('error', 'error')
        ],
        default='info'
    )

    def __str__(self):
        return f"{self.user} - {self.title}"

class ParticipantCategoryModel(models.Model):
    event = models.ForeignKey(Events, on_delete=models.CASCADE, related_name="categories")
    type = models.CharField(max_length=50)  # "Возрастная", "Весовая", "Мой вариант"
    name = models.CharField(max_length=256)
    minValue = models.IntegerField(blank=True, null=True)
    maxValue = models.IntegerField(blank=True, null=True)

    def __str__(self):
        return f"{self.name} ({self.type})"

class ParticipantCategoryAssignment(models.Model):
    participant = models.ForeignKey(Participants, on_delete=models.CASCADE)
    event = models.ForeignKey(Events, on_delete=models.CASCADE)
    category = models.ForeignKey(ParticipantCategoryModel, on_delete=models.CASCADE)

    class Meta:
        unique_together = ('participant', 'event')  # Один участник — одна категория в событии

