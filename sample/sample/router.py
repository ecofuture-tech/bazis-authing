from bazis.contrib.authing.routes import router as authing_router
from bazis.contrib.authing.services.password.router import router as password_router
from bazis.core.routing import BazisRouter


router = BazisRouter(prefix='/api/v1')
router.register(prefix='/authing', arg=authing_router)
router.register(prefix='/authing', arg=password_router)
router.register('users.router')
