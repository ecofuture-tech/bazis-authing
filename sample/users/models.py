from bazis.contrib.users.models_abstract import AnonymousUserAbstract, UserAbstract
from bazis.core.models_abstract import JsonApiMixin, UuidMixin


class User(JsonApiMixin, UuidMixin, UserAbstract):
    pass


class AnonymousUser(AnonymousUserAbstract):
    pass
