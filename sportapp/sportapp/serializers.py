from django.contrib.auth.hashers import make_password
from django.core.mail import send_mail
from django.conf import settings
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.urls import reverse
from allauth.account.models import EmailAddress, EmailConfirmation
from sportapp.models import Users, Participants, Organizers, Events, TeamsParticipants, Notifications, ParticipantCategoryModel 


class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = Users
        fields = ('email', 'password', 'username')

    @staticmethod
    def send_confirmation_email(request, user):
        email_address = user.emailaddress_set.get(email=user.email)
        confirmation = EmailConfirmation.create(email_address)
        key = confirmation.key

        confirm_url = f'{settings.FRONTEND_IP}/api/verify-email/{key}'

        subject = 'Подтвердите ваш email'
        message = f'Для подтверждения email перейдите по ссылке: {confirm_url}'
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])
            
        

    def create(self, validated_data):
        user = Users.objects.create(
            email=validated_data['email'],
            username=validated_data['username'],
            password=make_password(validated_data['password']),
        )
        EmailAddress.objects.create(user=user, email=user.email, primary=True, verified=False)
        self.send_confirmation_email(self.context['request'], user)  # Отправка письма
        return user


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        # Вызов стандартной логики валидации
        data = super().validate(attrs)

        # Получаем пользователя
        user = self.user

        # Проверяем, подтвержден ли email
        email_address = EmailAddress.objects.filter(user=user, email=user.email).first()
        if not email_address or not email_address.verified:
            raise serializers.ValidationError("Email не подтвержден. Пожалуйста, подтвердите ваш email.")

        # Добавляем дополнительные данные в ответ (опционально)
        data['username'] = user.username
        data['email'] = user.email
        data['role'] = user.role

        return data


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        if not Users.objects.filter(email=value).exists():
            raise serializers.ValidationError("Пользователь с такой почтой не найден.")
        return value


class PasswordResetConfirmSerializer(serializers.Serializer):
    uidb64 = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True)


class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True)

    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError('Старый пароль неверный.')
        return value

    def validate_new_password(self, value):
        if len(value) < 6:
            raise serializers.ValidationError('Пароль должен содержать минимум 8 символов.')
        return value

class ParticipantsSerializer(serializers.ModelSerializer):
    fullname = serializers.CharField(write_only=True, required=False)
    phone = serializers.CharField(write_only=True, required=False)
    role = serializers.CharField(write_only=True, required=False)

    institution = serializers.CharField(required=False, allow_null=True)
    numberOfCompetitions = serializers.IntegerField(required=False, allow_null=True)
    rating = serializers.IntegerField(required=False, allow_null=True)

    class Meta:
        model = Participants
        fields = [
            'id', 'user', 'institution', 'dateR', 'height', 'weight',
            'numberOfCompetitions', 'rating', 'fullname', 'phone', 'role'
        ]
        read_only_fields = ['user']

class OrganizerSerializer(serializers.ModelSerializer):
    fullname = serializers.CharField(write_only=True, required=False)
    phone = serializers.CharField(write_only=True, required=False)
    role = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = Organizers
        fields = ['id', 'user', 'orgName', 'orgEmail', 'orgPhone', 'orgAddress',
                   'phone', 'fullname', 'role']
        read_only_fields = ['user']

class ParticipantCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = ParticipantCategoryModel
        fields = ['type', 'name', 'minValue', 'maxValue']

class EventSerializer(serializers.ModelSerializer):
    organizer = serializers.PrimaryKeyRelatedField(read_only=True)
    status = serializers.CharField(required=False)
    participants = serializers.IntegerField(read_only=True)
    categories = ParticipantCategorySerializer(many=True, write_only=True)

    class Meta:
        model = Events
        fields = [
            'id', 'organizer', 'participants', 'name', 'description',
            'typeOfCompetition', 'startDate', 'startTime', 'endDate',
            'endTime', 'address', 'aLotOfParticipant', 'limitOfParticipants',
            'status', 'categories'
        ]
        read_only_fields = ['organizer', 'participants']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        request = self.context.get('request')
        if request and request.method == 'GET':
            self.fields.pop('organizer', None)
            self.fields['categories'] = ParticipantCategorySerializer(many=True, read_only=True)

    def create(self, validated_data):
        categories_data = validated_data.pop('categories', [])
        event = Events.objects.create(**validated_data)
        for category in categories_data:
            ParticipantCategoryModel.objects.create(event=event, **category)
        return event

    def update(self, instance, validated_data):
        categories_data = validated_data.pop('categories', None)
        instance = super().update(instance, validated_data)
        if categories_data is not None:
            instance.categories.all().delete()
            for category in categories_data:
                ParticipantCategoryModel.objects.create(event=instance, **category)
        return instance


class JoinEventSerializer(serializers.Serializer):
    event_id = serializers.IntegerField()
    team_name = serializers.CharField(required=False)  # Обязателен только для командного

class CreateTeamSerializer(serializers.Serializer):
    event_id = serializers.IntegerField()
    team_name = serializers.CharField()

class JoinTeamSerializer(serializers.Serializer):
    event_id = serializers.IntegerField()
    team_name = serializers.CharField()


class ParticipantSerializer(serializers.ModelSerializer):
    fullname = serializers.CharField(source='user.fullname')
    team = serializers.SerializerMethodField()
    teamParticipantStatus = serializers.SerializerMethodField()

    class Meta:
        model = Participants
        fields = ['id', 'fullname', 'dateR', 'height', 'weight', 'team', 'teamParticipantStatus']

    def get_team(self, obj):
        # Получаем первую команду участника
        team_part = TeamsParticipants.objects.filter(participant=obj).first()
        return team_part.team.name if team_part else None

    def get_teamParticipantStatus(self, obj):
        team_part = TeamsParticipants.objects.filter(participant=obj).first()
        return team_part.status if team_part else "Не указано"

class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notifications
        fields = ['id', 'title', 'message', 'timestamp', 'isRead', 'type']

class OrganizerDataSerializer(serializers.ModelSerializer):
    class Meta:
        model = Organizers
        exclude = ['user']

class ParticipantDataSerializer(serializers.ModelSerializer):
    institution = serializers.StringRelatedField()

    class Meta:
        model = Participants
        exclude = ['user']

class ProfileUserSerializer(serializers.ModelSerializer):
    organizer = serializers.SerializerMethodField()
    participant = serializers.SerializerMethodField()

    class Meta:
        model = Users
        fields = ['id', 'username', 'email', 'fullname', 'phone', 'role', 'organizer', 'participant']

    def get_organizer(self, obj):
        try:
            organizer = Organizers.objects.get(user=obj)
            return OrganizerDataSerializer(organizer).data
        except Organizers.DoesNotExist:
            return None

    def get_participant(self, obj):
        try:
            participant = Participants.objects.get(user=obj)
            return ParticipantDataSerializer(participant).data
        except Participants.DoesNotExist:
            return None

class EventResultSerializer(serializers.Serializer):
    category = serializers.CharField()
    team_name = serializers.CharField()
    place = serializers.IntegerField()
