import factory
from bazis_test_utils import factories_abstract
from entity.models import ChildEntity, DependentEntity, ExtendedEntity, ParentEntity
from users.models import User


class UserFactory(factory.django.DjangoModelFactory):
    username = factory.Sequence(lambda n: f'user{n}')
    password = factory.Faker('password')
    first_name = factory.Faker('first_name')
    last_name = factory.Faker('last_name')
    email = factory.Faker('email')

    class Meta:
        model = User


class ChildEntityFactory(factories_abstract.ChildEntityFactoryAbstract):
    class Meta:
        model = ChildEntity


class DependentEntityFactory(factories_abstract.DependentEntityFactoryAbstract):
    class Meta:
        model = DependentEntity


class ExtendedEntityFactory(factories_abstract.ExtendedEntityFactoryAbstract):
    class Meta:
        model = ExtendedEntity


class ParentEntityFactory(factories_abstract.ParentEntityFactoryAbstract):
    class Meta:
        model = ParentEntity
