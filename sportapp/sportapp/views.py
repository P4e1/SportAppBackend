from datetime import datetime, timedelta, date
from rest_framework.exceptions import ValidationError
from django.contrib.auth.hashers import make_password
from rest_framework.decorators import action
from django.db.models import Count
from django.contrib.auth.tokens import default_token_generator
from django.db import transaction
from rest_framework.exceptions import ValidationError, NotFound
from django.utils import timezone
from allauth.account.models import EmailConfirmation
from django.shortcuts import get_object_or_404
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from rest_framework import generics, status, viewsets
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from django.conf import settings
from django.urls import reverse
from django.core.mail import send_mail
from django.utils.encoding import force_bytes, force_str
from .models import Users, Participants, Organizers, Events, TeamsParticipants, Teams, ParticipantCategoryAssignment, ParticipantCategoryModel
from .serializers import UserRegistrationSerializer, CustomTokenObtainPairSerializer, PasswordResetRequestSerializer, \
    PasswordResetConfirmSerializer, PasswordChangeSerializer, ParticipantsSerializer, OrganizerSerializer, EventSerializer, \
    JoinEventSerializer, JoinTeamSerializer, CreateTeamSerializer, NotificationSerializer, ProfileUserSerializer, EventResultSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.renderers import JSONRenderer
from django.views import View
from django.shortcuts import render
from django.http import JsonResponse, HttpResponseNotAllowed
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework import status
from .serializers import ParticipantSerializer
from .models import Events, Participants, TeamsParticipants, Notifications
from django.shortcuts import get_object_or_404


class UserRegistrationView(generics.CreateAPIView):
    serializer_class = UserRegistrationSerializer
    permission_classes = []
    renderer_classes = [JSONRenderer]


class VerifyEmailView(APIView):
    permission_classes = []

    def post(self, request, key):
        email_confirmation = get_object_or_404(EmailConfirmation, key=key)

        # Убедимся, что поле `sent` установлено
        if email_confirmation.sent is None:
            email_confirmation.sent = timezone.now()
            email_confirmation.save()

        email_confirmation.confirm(request)
        return Response({'status': 'email verified'})

    def get(self, request, key):
        # Показываем HTML с auto-POST
        return render(request, 'verify_email.html', {'key': key})


class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer


class LogoutView(APIView):
    def post(self, request):
        try:
            refresh_token = request.data['refresh']
            token = RefreshToken(refresh_token)
            token.blacklist()  # Добавляем refresh-токен в черный список
            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response(status=status.HTTP_400_BAD_REQUEST)


class PasswordResetRequestView(APIView):
    permission_classes = []
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = Users.objects.get(email=email)
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            reset_url = f"{settings.FRONTEND_IP}/api/password/reset/confirm1/{uid}/{token}/"
            send_mail(
                'Сброс пароля',
                f'Перейдите по ссылке для сброса пароля: {reset_url}',
                settings.EMAIL_HOST_USER,
                [email],
                fail_silently=False,
            )
            return Response({"message": "Ссылка для сброса пароля отправлена на ваш email."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetConfirmView(APIView):
    permission_classes = []
    def post(self, request, uidb64, token):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if serializer.is_valid():
            try:
                uid = force_str(urlsafe_base64_decode(serializer.validated_data['uidb64']))
                user = Users.objects.get(pk=uid)
                token = serializer.validated_data['token']
                if default_token_generator.check_token(user, token):
                    user.set_password(serializer.validated_data['new_password'])
                    user.save()
                    return Response({"message": "Пароль успешно изменен."}, status=status.HTTP_200_OK)
                else:
                    return Response({"error": "Неверный токен."}, status=status.HTTP_400_BAD_REQUEST)
            except (TypeError, ValueError, OverflowError, Users.DoesNotExist):
                return Response({"error": "Неверный UID."}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

    def get(self, request, uidb64, token):
    # Отображаем HTML с auto-POST
        return render(request, 'password_reset_confirm.html', {
            'uidb64': uidb64,
            'token': token
        })


class PasswordChangeView(APIView):
    def post(self, request):
        serializer = PasswordChangeSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            user = request.user
            new_password = make_password(serializer.validated_data['new_password'])
            user.password = new_password
            user.save()
            return Response({'message': 'Пароль успешно изменен.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ParticipantsViewSet(viewsets.ModelViewSet):
    serializer_class = ParticipantsSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Participants.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        user = self.request.user

        # Проверка возраста по dateR
        dateR = serializer.validated_data.get('dateR')
        if dateR:
            today = date.today()
            min_birth_date = date(today.year - 14, today.month, today.day)
            if dateR > min_birth_date:
                raise ValidationError("Возраст участника должен быть не менее 14 лет.")

        # Извлекаем и удаляем данные для профиля пользователя
        fullname = serializer.validated_data.pop('fullname', None)
        phone = serializer.validated_data.pop('phone', None) 
        role = serializer.validated_data.pop('role', None)

        if fullname is not None:
            user.fullname = fullname
        if phone is not None:
            user.phone = phone
        if role is not None:
            user.role = role
        user.save()

        serializer.save(user=user)

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.user != request.user:
            raise PermissionDenied("Вы не можете изменять эту запись.")
        return super().update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.user != request.user:
            raise PermissionDenied("Вы не можете удалить эту запись.")
        return super().destroy(request, *args, **kwargs)
    
class NotificationsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        notifications = Notifications.objects.filter(user=user).order_by('-timestamp')
        serializer = NotificationSerializer(notifications, many=True)
        return Response(serializer.data)

class ProfileUserView(viewsets.ModelViewSet):
    serializer_class = ProfileUserSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Users.objects.filter(id=self.request.user.id)

    def get_object(self):
        return self.request.user  # всегда возвращаем текущего пользователя

    def update(self, request, *args, **kwargs):
        if self.get_object().id != request.user.id:
            raise PermissionDenied("Вы не можете изменять чужой профиль.")
        return super().update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        if self.get_object().id != request.user.id:
            raise PermissionDenied("Вы не можете удалить чужой профиль.")
        return super().destroy(request, *args, **kwargs)
    
class OrganizersViewSet(viewsets.ModelViewSet):
    serializer_class = OrganizerSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Organizers.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        user = self.request.user

        # Извлекаем и удаляем fullname и phone перед сохранением участника
        fullname = serializer.validated_data.pop('fullname', None)
        phone = serializer.validated_data.pop('phone', None) 
        role = serializer.validated_data.pop('role', None)

        # Обновляем пользователя, если данные пришли
        if fullname is not None:
            user.fullname = fullname
        if phone is not None:
            user.phone = phone
        if role is not None:
            user.role = role
        user.save()

        # Сохраняем участника
        serializer.save(user=user)

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.user != request.user:
            raise PermissionDenied("Вы не можете изменять эту запись.")
        return super().update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.user != request.user:
            raise PermissionDenied("Вы не можете удалить эту запись.")
        return super().destroy(request, *args, **kwargs)

class EventsView(viewsets.ModelViewSet):
    serializer_class = EventSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user

        try:
            organizer = Organizers.objects.get(user=user)
            return Events.objects.filter(organizer=organizer)
        except Organizers.DoesNotExist:
            try:
                participant = Participants.objects.get(user=user)
                return Events.objects.filter(
                    teams__teamsparticipants__participant=participant, status__in=["Регистрация открыта", "Регистрация закрыта", "Завершено", "Идёт"]
                ).distinct()
            except Participants.DoesNotExist:
                return Events.objects.none()

    def perform_create(self, serializer):
        try:
            organizer = Organizers.objects.get(user=self.request.user)
        except Organizers.DoesNotExist:
            raise PermissionDenied("Организатор не найден.")

        start_date = serializer.validated_data['startDate']
        start_time = serializer.validated_data['startTime']
        end_date = serializer.validated_data['endDate']
        end_time = serializer.validated_data['endTime']
        address = serializer.validated_data['address']

        start_dt = datetime.combine(start_date, start_time)
        end_dt = datetime.combine(end_date, end_time)

        if start_dt >= end_dt:
            raise ValidationError("Дата и время начала должны быть раньше даты и времени окончания.")

        existing_events = Events.objects.filter(organizer=organizer, address=address)
        for event in existing_events:
            event_start = datetime.combine(event.startDate, event.startTime)
            event_end = datetime.combine(event.endDate, event.endTime)
            if start_dt < event_end and end_dt > event_start:
                raise ValidationError(f"Событие пересекается с другим: '{event.name}'")
            

        serializer.save(organizer=organizer, status="Проверка")



    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        if not request.user.is_superuser:
            if not instance.organizer or instance.organizer.user != request.user:
                raise PermissionDenied("Вы не можете изменять эту запись.")
        return super().update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if not request.user.is_superuser:
            if not instance.organizer or instance.organizer.user != request.user:
                raise PermissionDenied("Вы не можете удалить эту запись.")
        return super().destroy(request, *args, **kwargs)
    
    @action(detail=False, methods=["post"], url_path="join")
    def join_event(self, request):
        serializer = JoinEventSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        event_id = serializer.validated_data["event_id"]
        team_name = serializer.validated_data.get("team_name")

        event = get_object_or_404(Events, pk=event_id)
        participant = get_object_or_404(Participants, user=request.user)

        if TeamsParticipants.objects.filter(participant=participant, team__event=event).exists():
            return Response({
                "success": False,
                "message": "Вы уже участвуете в этом событии",
                "is_joined": True,
                "current_participants": TeamsParticipants.objects.filter(
                    team__event=event, status__in=["Подтверждён", "Проверка"]
                ).count()
            }, status=200)

        with transaction.atomic():
            if event.typeOfCompetition == "Индивидуальный":
                auto_team_name = f"{request.user.fullname} — индивидуально"
                team = Teams.objects.create(event=event, name=auto_team_name)
            elif event.typeOfCompetition == "Командный":
                if not team_name:
                    raise ValidationError("Необходимо указать название команды")
                team, _ = Teams.objects.get_or_create(event=event, name=team_name)
            else:
                raise ValidationError("Неизвестный тип соревнования")

            TeamsParticipants.objects.create(team=team, participant=participant, status="Проверка")

            categories = ParticipantCategoryModel.objects.filter(event=event)
            category = self._pick_best_category(participant, categories)
            if not category:
                raise ValidationError("Не удалось определить подходящую категорию")

            ParticipantCategoryAssignment.objects.create(
                participant=participant,
                event=event,
                category=category
            )

            if event.limitOfParticipants != event.aLotOfParticipant:
                event.aLotOfParticipant += 1
                event.save()

        return Response({
            "success": True,
            "message": "Вы успешно присоединились к событию",
            "is_joined": True,
            "current_participants": TeamsParticipants.objects.filter(
                team__event=event, status__in=["Подтверждён", "Проверка"]
            ).count()
        })

    @action(detail=False, methods=["post"], url_path="leave")
    def leave_event(self, request):
        event_id = request.data.get("event_id")
        if not event_id:
            raise ValidationError("event_id обязателен")

        try:
            event = Events.objects.get(pk=event_id)
        except Events.DoesNotExist:
            raise NotFound("Событие не найдено")

        try:
            participant = Participants.objects.get(user=request.user)
        except Participants.DoesNotExist:
            raise ValidationError("Вы не зарегистрированы как участник")

        # Удаление участника из команды в рамках события
        joined_entries = TeamsParticipants.objects.filter(participant=participant, team__event=event)
        if not joined_entries.exists():
            return Response({
                "success": False,
                "message": "Вы не участвуете в этом событии",
                "is_joined": False,
                "current_participants": TeamsParticipants.objects.filter(team__event=event, status__in= ["Подтверждён","Проверка"]).count()
            })

        with transaction.atomic():
            # Удаляем связи
            joined_entries.delete()
            ParticipantCategoryAssignment.objects.filter(participant=participant, event=event).delete()
            # Удаляем пустые команды
            Teams.objects.filter(event=event).annotate(count=Count('teamsparticipants')).filter(count=0).delete()
            event.aLotOfParticipant = max(0, event.aLotOfParticipant - 1)
            event.save()
            participant = Participants.objects.get(user=request.user)
            ParticipantCategoryAssignment.objects.filter(event=event, participant=participant).delete()


        return Response({
            "success": True,
            "message": "Вы покинули событие",
            "is_joined": False,
            "current_participants": TeamsParticipants.objects.filter(team__event=event, status__in= ["Подтверждён","Проверка"]).count()
        })

    @action(detail=True, methods=["get"], url_path="join-status")
    def check_user_join_status(self, request, pk=None):
        try:
            event = Events.objects.get(pk=pk)
        except Events.DoesNotExist:
            raise NotFound("Событие не найдено")

        try:
            participant = Participants.objects.get(user=request.user)
        except Participants.DoesNotExist:
            return Response({
                "success": True,
                "message": "Вы не зарегистрированы как участник",
                "is_joined": False
            })

        team_part = TeamsParticipants.objects.filter(participant=participant, team__event=event).first()
        if not team_part:
            return Response({
                "success": True,
                "message": "Вы не участвуете в этом событии",
                "is_joined": False
            })

        return Response({
            "success": True,
            "is_joined": True,
            "status": team_part.status
        })

    @action(detail=False, methods=["post"], url_path="teams/create")
    def create_team(self, request):
        serializer = CreateTeamSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        event_id = serializer.validated_data["event_id"]
        team_name = serializer.validated_data["team_name"]

        event = get_object_or_404(Events, pk=event_id)
        participant = get_object_or_404(Participants, user=request.user)

        if event.typeOfCompetition != "Командный":
            raise ValidationError("Команды можно создавать только для командных соревнований")

        if Teams.objects.filter(event=event, name=team_name).exists():
            raise ValidationError("Команда с таким названием уже существует")

        with transaction.atomic():
            team = Teams.objects.create(event=event, name=team_name)
            TeamsParticipants.objects.create(team=team, participant=participant, status="Проверка")

            # Назначение категории
            categories = ParticipantCategoryModel.objects.filter(event=event)
            category = self._pick_best_category(participant, categories)

            if not category:
                category = categories.filter(type="Общая").first()
                if not category:
                    category = ParticipantCategoryModel.objects.create(
                        event=event,
                        name="Общая категория",
                        type="Общая"
                    )

            ParticipantCategoryAssignment.objects.get_or_create(
                participant=participant,
                event=event,
                category=category
            )

            if event.limitOfParticipants != event.aLotOfParticipant:
                event.aLotOfParticipant += 1
                event.save()

        return Response({
            "success": True,
            "message": "Команда успешно создана и вы присоединились",
            "team_id": team.id,
            "team_name": team.name
        })

    @action(detail=False, methods=["post"], url_path="join")
    def join_event(self, request):
        try:
            serializer = JoinEventSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            event_id = serializer.validated_data["event_id"]
            team_name = serializer.validated_data.get("team_name")

            event = get_object_or_404(Events, pk=event_id)
            participant = get_object_or_404(Participants, user=request.user)

            if TeamsParticipants.objects.filter(participant=participant, team__event=event).exists():
                return Response({
                    "success": False,
                    "message": "Вы уже участвуете в этом событии",
                    "is_joined": True,
                    "current_participants": TeamsParticipants.objects.filter(
                        team__event=event, status__in=["Подтверждён", "Проверка"]
                    ).count()
                }, status=200)

            with transaction.atomic():
                # Создание команды
                try:
                    if event.typeOfCompetition == "Индивидуальный":
                        auto_team_name = f"{request.user.fullname} — индивидуально"
                        team = Teams.objects.create(event=event, name=auto_team_name)
                    elif event.typeOfCompetition == "Командный":
                        if not team_name:
                            raise ValidationError("Необходимо указать название команды")
                        team, _ = Teams.objects.get_or_create(event=event, name=team_name)
                    else:
                        raise ValidationError("Неизвестный тип соревнования")
                except Exception as e:
                    print(f"Ошибка создания команды: {e}")
                    raise ValidationError(f"Ошибка создания команды: {str(e)}")

                # Создание связи участник-команда
                TeamsParticipants.objects.create(team=team, participant=participant, status="Проверка")

                # Работа с категориями
                try:
                    categories = ParticipantCategoryModel.objects.filter(event=event)
                    print(f"Найдено категорий: {categories.count()}")
                    
                    if categories.exists():
                        category = self._pick_best_category(participant, categories)
                        
                        if not category:
                            # Пытаемся найти универсальную категорию
                            category = categories.filter(
                                type="Общая"
                            ).first()
                            
                            if not category:
                                # Создаем универсальную категорию
                                category = ParticipantCategoryModel.objects.create(
                                    event=event,
                                    name="Общая категория",
                                    type="Общая",
                                    minValue=None,
                                    maxValue=None
                                )
                                print("Создана общая категория")
                    else:
                        # Если категорий нет вообще, создаем одну
                        category = ParticipantCategoryModel.objects.create(
                            event=event,
                            name="Общая категория",
                            type="Общая",
                            minValue=None,
                            maxValue=None
                        )
                        print("Создана первая категория для события")

                    # Назначаем категорию участнику
                    ParticipantCategoryAssignment.objects.create(
                        participant=participant,
                        event=event,
                        category=category
                    )
                    
                except Exception as e:
                    print(f"Ошибка работы с категориями: {e}")
                    # Не прерываем выполнение, но логируем ошибку
                    import traceback
                    traceback.print_exc()

                # Обновляем счетчик участников
                if event.limitOfParticipants != event.aLotOfParticipant:
                    event.aLotOfParticipant += 1
                    event.save()

            return Response({
                "success": True,
                "message": "Вы успешно присоединились к событию",
                "is_joined": True,
                "current_participants": TeamsParticipants.objects.filter(
                    team__event=event, status__in=["Подтверждён", "Проверка"]
                ).count()
            })
            
        except ValidationError as e:
            print(f"ValidationError: {e}")
            return Response({
                "success": False,
                "message": str(e)
            }, status=400)
        except Exception as e:
            print(f"Неожиданная ошибка: {e}")
            import traceback
            traceback.print_exc()
            return Response({
                "success": False,
                "message": "Произошла внутренняя ошибка сервера"
            }, status=500)
    @action(detail=True, methods=["get"], url_path="teams")
    def get_event_teams(self, request, pk=None):
        try:
            event = Events.objects.get(pk=pk)
        except Events.DoesNotExist:
            raise NotFound("Событие не найдено")

        teams = Teams.objects.filter(event=event).values("id", "name")

        return Response({
            "success": True,
            "teams": list(teams)
        })

    @action(detail=False, methods=["get"], url_path="all")
    def get_all_events(self, request):
        user = request.user
        try:
            participant = Participants.objects.get(user=user)
            queryset = Events.objects.filter(status__in=[
                "Регистрация открыта",
                "Регистрация закрыта",
                "Идёт"
            ])
        except Participants.DoesNotExist:
            queryset = Events.objects.all()

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)
    
    @action(detail=True, methods=["get"], url_path="participants")
    def get_event_participants(self, request, pk=None):
        event = get_object_or_404(Events, pk=pk)

        # Проверка, имеет ли право организатор просматривать участников
        if not request.user.is_superuser and (not event.organizer or event.organizer.user != request.user):
            raise PermissionDenied("Нет доступа к участникам этого события.")

        participants_qs = Participants.objects.filter(
            teamsparticipants__team__event=event,
            teamsparticipants__status__in=["Подтверждён", "Проверка"]
        ).distinct()



        serializer = ParticipantSerializer(participants_qs, many=True)
        return Response(serializer.data, status=200)
    
    @action(detail=True, methods=["put"], url_path="participants/(?P<participant_id>[^/.]+)/confirm")
    def confirm_participant(self, request, pk=None, participant_id=None):
        event = get_object_or_404(Events, pk=pk)
        if not request.user.is_superuser and (not event.organizer or event.organizer.user != request.user):
            raise PermissionDenied("Нет доступа")

        participant = get_object_or_404(Participants, pk=participant_id)

        team_part = TeamsParticipants.objects.filter(team__event=event, participant=participant).first()
        if not team_part:
            return Response({"detail": "Участник не найден в этом событии."}, status=404)

        # Обновляем статус на "Подтверждён"
        team_part.status = "Подтверждён"
        team_part.save()

        return Response({"message": "Участник подтверждён"}, status=200)

    
    @action(detail=True, methods=["put"], url_path="participants/(?P<participant_id>[^/.]+)/reject")
    def reject_participant(self, request, pk=None, participant_id=None):
        event = get_object_or_404(Events, pk=pk)
        if not request.user.is_superuser and (not event.organizer or event.organizer.user != request.user):
            raise PermissionDenied("Нет доступа")
        
        # Используем более точную фильтрацию напрямую
        team_part = get_object_or_404(
            TeamsParticipants, 
            team__event=event, 
            participant_id=participant_id
        )
        
        # Проверяем уникальность записи
        matching_records = TeamsParticipants.objects.filter(
            team__event=event, 
            participant_id=participant_id
        )
        
        if matching_records.count() > 1:
            return Response(
                {"detail": "Найдено несколько записей участника"}, 
                status=400
            )
        
        # Если участник ранее был подтвержден — уменьшаем счётчик
        if team_part.status == "Подтверждён":
            event.aLotOfParticipant = max(0, event.aLotOfParticipant - 1)
            event.save()
        
        # Обновляем статус конкретной записи
        old_status = team_part.status
        team_part.status = "Отклонён"
        team_part.save()
        
        # Для отладки
        return Response({
            "message": f"Участник отклонён (было: {old_status}, стало: {team_part.status})",
            "participant_id": participant_id,
            "team_part_id": team_part.id
        }, status=200)
    @action(detail=True, methods=["post", "get"], url_path="results")
    def manage_event_results(self, request, pk=None):
        event = get_object_or_404(Events, pk=pk)

        if not request.user.is_superuser and (not event.organizer or event.organizer.user != request.user):
            raise PermissionDenied("Нет доступа к результатам")

        if request.method == "GET":
            # Получение результатов (ваш старый код)
            results = []
            teams = Teams.objects.filter(event=event)

            for team in teams:
                tp = TeamsParticipants.objects.filter(team=team, place__isnull=False).first()
                if not tp:
                    continue

                assignment = ParticipantCategoryAssignment.objects.filter(
                    participant=tp.participant,
                    event=event
                ).first()

                if assignment:
                    results.append({
                        "category": assignment.category.name,
                        "team_name": team.name,
                        "place": tp.place
                    })

            serializer = EventResultSerializer(results, many=True)
            return Response(serializer.data)

        elif request.method == "POST":
            # Сохранение результатов из списка
            results_data = request.data.get('results', [])
            
            if not results_data:
                return Response(
                    {"detail": "Поле 'results' обязательно"}, 
                    status=400
                )

            updated_results = []
            errors = []

            for index, result in enumerate(results_data):
                try:
                    # Валидация входных данных
                    category_name = result.get('category')
                    team_name = result.get('team_name')
                    place = result.get('place')

                    if not all([category_name, team_name, place is not None]):
                        errors.append(f"Результат {index + 1}: отсутствуют обязательные поля")
                        continue

                    # Проверяем место (должно быть положительным числом)
                    try:
                        place = int(place)
                        if place <= 0:
                            errors.append(f"Результат {index + 1}: место должно быть положительным числом")
                            continue
                    except (ValueError, TypeError):
                        errors.append(f"Результат {index + 1}: некорректное значение места")
                        continue

                    # Находим команду
                    team = Teams.objects.filter(event=event, name=team_name).first()
                    if not team:
                        errors.append(f"Результат {index + 1}: команда '{team_name}' не найдена")
                        continue

                    # Находим категорию
                    category = ParticipantCategoryModel.objects.filter(name=category_name).first()
                    if not category:
                        errors.append(f"Результат {index + 1}: категория '{category_name}' не найдена")
                        continue

                    # Находим участника команды для данной категории
                    team_participant = None
                    team_participants = TeamsParticipants.objects.filter(team=team)
                    
                    for tp in team_participants:
                        assignment = ParticipantCategoryAssignment.objects.filter(
                            participant=tp.participant,
                            event=event,
                            category=category
                        ).first()
                        
                        if assignment:
                            team_participant = tp
                            break

                    if not team_participant:
                        errors.append(
                            f"Результат {index + 1}: не найден участник команды '{team_name}' "
                            f"в категории '{category_name}'"
                        )
                        continue

                    # Обновляем место
                    old_place = team_participant.place
                    team_participant.place = place
                    team_participant.save()

                    updated_results.append({
                        "category": category_name,
                        "team_name": team_name,
                        "place": place,
                        "previous_place": old_place,
                        "participant_id": team_participant.participant.id
                    })

                except Exception as e:
                    errors.append(f"Результат {index + 1}: ошибка обработки - {str(e)}")

            # Формируем ответ
            response_data = {
                "updated_count": len(updated_results),
                "updated_results": updated_results
            }

            if errors:
                response_data["errors"] = errors
                response_data["errors_count"] = len(errors)

            status_code = 200 if updated_results else 400
            return Response(response_data, status=status_code)
    
    # Дополнительно: отдельный метод только для обновления результатов
    @action(detail=True, methods=["post"], url_path="results/update")
    def update_event_results(self, request, pk=None):
        """
        Обновление результатов события.
        
        Ожидает JSON в формате:
        {
            "results": [
                {
                    "category": "Название категории",
                    "team_name": "Название команды", 
                    "place": 1
                },
                ...
            ]
        }
        """
        event = get_object_or_404(Events, pk=pk)

        if not request.user.is_superuser and (not event.organizer or event.organizer.user != request.user):
            raise PermissionDenied("Нет доступа к результатам")

        results_data = request.data.get('results', [])
        
        if not isinstance(results_data, list):
            return Response(
                {"detail": "Поле 'results' должно быть списком"}, 
                status=400
            )

        if not results_data:
            return Response(
                {"detail": "Список результатов не может быть пустым"}, 
                status=400
            )

        # Используем транзакцию для атомарности операции
        from django.db import transaction
        
        try:
            with transaction.atomic():
                updated_results = []
                errors = []

                for index, result in enumerate(results_data):
                    try:
                        # Валидация
                        required_fields = ['category', 'team_name', 'place']
                        missing_fields = [field for field in required_fields if not result.get(field)]
                        
                        if missing_fields:
                            errors.append(
                                f"Результат {index + 1}: отсутствуют поля: {', '.join(missing_fields)}"
                            )
                            continue

                        category_name = result['category'].strip()
                        team_name = result['team_name'].strip()
                        place = result['place']

                        # Валидация места
                        try:
                            place = int(place)
                            if place <= 0:
                                raise ValueError("Место должно быть положительным")
                        except (ValueError, TypeError):
                            errors.append(f"Результат {index + 1}: некорректное место '{place}'")
                            continue

                        # Поиск команды
                        team = Teams.objects.filter(event=event, name=team_name).first()
                        if not team:
                            errors.append(f"Результат {index + 1}: команда '{team_name}' не найдена")
                            continue

                        # Поиск категории
                        category = ParticipantCategoryModel.objects.filter(name=category_name).first()
                        if not category:
                            errors.append(f"Результат {index + 1}: категория '{category_name}' не найдена")
                            continue

                        # Поиск участника команды в данной категории
                        team_participants = TeamsParticipants.objects.filter(team=team)
                        target_participant = None

                        for tp in team_participants:
                            if ParticipantCategoryAssignment.objects.filter(
                                participant=tp.participant,
                                event=event,
                                category=category
                            ).exists():
                                target_participant = tp
                                break

                        if not target_participant:
                            errors.append(
                                f"Результат {index + 1}: участник команды '{team_name}' "
                                f"не найден в категории '{category_name}'"
                            )
                            continue

                        # Обновление места
                        old_place = target_participant.place
                        target_participant.place = place
                        target_participant.save()

                        updated_results.append({
                            "index": index + 1,
                            "category": category_name,
                            "team_name": team_name,
                            "place": place,
                            "old_place": old_place,
                            "team_id": team.id,
                            "participant_id": target_participant.participant.id
                        })

                    except Exception as e:
                        errors.append(f"Результат {index + 1}: неожиданная ошибка - {str(e)}")

                # Если есть ошибки, откатываем транзакцию
                if errors:
                    transaction.set_rollback(True)
                    return Response({
                        "success": False,
                        "message": "Обновление отменено из-за ошибок",
                        "errors": errors,
                        "processed": len(results_data),
                        "updated": 0
                    }, status=400)

                return Response({
                    "success": True,
                    "message": f"Успешно обновлено {len(updated_results)} результатов",
                    "updated_results": updated_results,
                    "processed": len(results_data),
                    "updated": len(updated_results)
                })

        except Exception as e:
            return Response({
                "success": False,
                "message": f"Критическая ошибка: {str(e)}"
            }, status=500)
    
    def _calculate_age(self, birth_date):
        """Вынесен в отдельный метод для переиспользования"""
        if not birth_date:
            return None
        today = date.today()
        return today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))

    def _pick_best_category(self, participant, categories):
        """Улучшенный метод выбора категории"""
        try:
            if not categories.exists():
                print("Категории не найдены")
                return None
            
            # Вычисляем возраст участника
            age = None
            if hasattr(participant, 'dateR') and participant.dateR:
                age = self._calculate_age(participant.dateR)
            
            # Получаем вес участника
            weight = None
            if hasattr(participant, 'weight') and participant.weight:
                weight = participant.weight
            
            print(f"Поиск категории для участника: возраст={age}, вес={weight}")
            
            for category in categories:
                try:
                    print(f"Проверяем категорию: {category.name}, тип: {getattr(category, 'type', 'не указан')}")
                    
                    category_type = getattr(category, 'type', None)
                    
                    if category_type == "Возрастная" and age is not None:
                        min_age = 2025 - getattr(category, 'maxValue', None)
                        max_age = 2025 - getattr(category, 'minValue', None)
                        print(f"Минимальное знач: {min_age}; Максимальное знач: {max_age}")
                        # Проверяем возрастные ограничения
                        if (min_age is None or age >= min_age) and (max_age is None or age <= max_age):
                            print(f"Найдена подходящая возрастная категория: {category.name}")
                            return category
                            
                    elif category_type == "Весовая" and weight is not None:
                        min_weight = getattr(category, 'minValue', None)
                        max_weight = getattr(category, 'maxValue', None)
                        
                        # Проверяем весовые ограничения
                        if (min_weight is None or weight >= min_weight) and (max_weight is None or weight <= max_weight):
                            print(f"Найдена подходящая весовая категория: {category.name}")
                            return category
                            
                    elif category_type is None or category_type == "" or category_type == "Общая":
                        # Универсальная категория без ограничений
                        print(f"Найдена универсальная категория: {category.name}")
                        return category
                        
                except Exception as e:
                    print(f"Ошибка при проверке категории {category.name}: {e}")
                    continue
            
            print("Подходящая категория не найдена")
            return None
            
        except Exception as e:
            print(f"Ошибка в _pick_best_category: {e}")
            return None