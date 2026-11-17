import asyncio
from contextlib import asynccontextmanager
import logging
from pathlib import Path
import sqlite3

from fastapi.staticfiles import StaticFiles

from app.main import app
from app.p17_snapshot import SnapshotError
from app.portal_p17_refresh import refresh

runtime = Path(__file__).resolve().parent
source = Path('/var/lib/db-firewall-p17/state.sqlite3')
snapshot = runtime / 'data' / 'p17.json'
portal_lifespan = app.router.lifespan_context

async def refresh_p17():
    while True:
        try:
            await asyncio.to_thread(refresh, source, snapshot)
        except (OSError, ValueError, sqlite3.Error, SnapshotError) as exc:
            logging.getLogger('uvicorn.error').warning(
                'P17 refresh failed (%s). Last good snapshot preserved.', type(exc).__name__
            )
        await asyncio.sleep(15)

@asynccontextmanager
async def lifespan(application):
    async with portal_lifespan(application):
        task = asyncio.create_task(refresh_p17())
        try:
            yield
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

app.router.lifespan_context = lifespan
app.mount('/', StaticFiles(directory=runtime / 'n91-portal-proxy-linux' / 'web', html=True), name='portal-web')
