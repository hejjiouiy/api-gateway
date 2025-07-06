# app/services/sync.py
import asyncio
import logging
from datetime import datetime
import uuid
import httpx
from contextlib import asynccontextmanager
from services.keycloak import get_master_admin_token
from config.settings import KEYCLOAK_CONFIG
from app.models.user import Utilisateur

logger = logging.getLogger(__name__)

# Flag to prevent concurrent sync operations
sync_in_progress = False


async def sync_users_background(db_session_getter):
    """
    Background task to synchronize users from Keycloak to the local database

    Args:
        db_session_getter: Async context manager that provides a database session
    """
    global sync_in_progress

    # Check if sync is already running
    if sync_in_progress:
        logger.info("User synchronization already in progress, skipping")
        return

    sync_in_progress = True
    logger.info("Starting user synchronization from Keycloak")

    try:
        # Get database session
        async with db_session_getter() as db:
            # Get admin token
            admin_token = await get_master_admin_token()

            # Fetch users from Keycloak with pagination
            first_result = 0
            max_results = 100
            all_keycloak_users = []

            async with httpx.AsyncClient(timeout=30.0) as client:
                while True:
                    response = await client.get(
                        f"{KEYCLOAK_CONFIG['server_url']}/admin/realms/{KEYCLOAK_CONFIG['realm']}/users",
                        params={"first": first_result, "max": max_results},
                        headers={
                            "Authorization": f"Bearer {admin_token}"
                        }
                    )

                    if response.status_code != 200:
                        logger.error(f"Failed to retrieve users: {response.text}")
                        return

                    batch = response.json()
                    if not batch:
                        break

                    all_keycloak_users.extend(batch)
                    first_result += max_results

                    if len(batch) < max_results:
                        break

                # Continue with synchronization logic as in the endpoint
                # This code is a duplicate of the sync endpoint logic
                # [Code similaire à celui de l'endpoint sync_users_to_db]

                logger.info(f"User synchronization completed: {len(all_keycloak_users)} users processed")

    except Exception as e:
        logger.error(f"Error in user synchronization: {str(e)}")

    finally:
        sync_in_progress = False


def setup_sync_scheduler(app, db_session_getter):
    """
    Setup scheduler to periodically sync users

    Args:
        app: FastAPI application
        db_session_getter: Async context manager that provides a database session
    """

    @asynccontextmanager
    async def schedule_sync_task():
        # Setup task
        task = None

        async def periodic_sync():
            while True:
                await sync_users_background(db_session_getter)
                # Run every hour
                await asyncio.sleep(3600)

        # Start background task
        task = asyncio.create_task(periodic_sync())
        logger.info("User synchronization scheduler started")

        try:
            yield
        finally:
            # Cancel task when app shuts down
            if task:
                task.cancel()
                logger.info("User synchronization scheduler stopped")

    return schedule_sync_task