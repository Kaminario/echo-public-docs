import fastapi

from .host import router as host_router
from .instant_extract import router as instant_extract_router
from .status import router as status_router

router = fastapi.APIRouter()

router.include_router(host_router)
router.include_router(instant_extract_router)
router.include_router(status_router)
