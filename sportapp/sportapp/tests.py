from django.test import TestCase
from sportapp.models import Users

class StudentCardModelTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        # Создаем пользователя 
        cls.user = Users.objects.create(username='testuser', fullname='Test User')

    def student_card_creation(self):
        """Проверяем, что студенческая карточка создана корректно."""
        self.assertEqual(self.user.name, 'John')
        self.assertEqual(self.student_card.surname, 'Doe')
        self.assertEqual(self.student_card.contacts, '1234567890')
        self.assertEqual(self.student_card.comment, 'Test comment')
        self.assertEqual(self.student_card.address, 'Test address')
        self.assertEqual(self.student_card.lesson_price, 100.00)

    def test_student_card_str_method(self):
        """Проверяем метод __str__."""
        self.assertEqual(str(self.fullname), 'John Doe')