# app/api/endpoints/users.py
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
import httpx
import logging
import uuid
from datetime import datetime
from services.keycloak import get_master_admin_token
from config.settings import KEYCLOAK_CONFIG, RATE_LIMIT_ADMIN
from utils import RateLimiter
from api.dependencies import require_roles
from app.models.user import Utilisateur
from app.repositories import user_repo
from dependencies import get_db

router = APIRouter(prefix="/users", tags=["users"])
rate_limiter = RateLimiter()
logger = logging.getLogger(__name__)


@router.get("")
async def get_users(
        request: Request,
        max_results: int = 100,
        first_result: int = 0,
        search: str = "",
        include_roles: bool = True,
        user: dict = Depends(require_roles(["admin"]))
):
    """
    Retrieve all users from Keycloak including their roles.
    This endpoint requires admin privileges.
    """
    # Rate limiting for admin operations
    client_ip = request.client.host
    if not rate_limiter.check(f"admin_operations:{client_ip}", RATE_LIMIT_ADMIN, 60):
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded for admin operations"
        )

    # Create the admin token
    admin_token = await get_master_admin_token()

    # Construct the query parameters
    query_params = {
        "max": max_results,
        "first": first_result
    }

    if search:
        query_params["search"] = search

    # Call the Keycloak Admin API
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Get users
            response = await client.get(
                f"{KEYCLOAK_CONFIG['server_url']}/admin/realms/{KEYCLOAK_CONFIG['realm']}/users",
                params=query_params,
                headers={
                    "Authorization": f"Bearer {admin_token}"
                }
            )

            if response.status_code != 200:
                logger.error(f"Failed to retrieve users: {response.text}")
                raise HTTPException(
                    status_code=response.status_code,
                    detail=response.text
                )

            users_data = response.json()
            users = []

            # Get role mappings for each user if requested
            for user_data in users_data:
                attributes = user_data.get("attributes", {})
                user_id = user_data.get("id")
                user = {
                    "id": user_data.get("id"),
                    "username": user_data.get("username"),
                    "email": user_data.get("email"),
                    "prenom": user_data.get("firstName"),
                    "nom": user_data.get("lastName"),
                    "statut": attributes.get("statut", [None])[0],
                    "unite": attributes.get("unite", [None])[0],
                    "telephone": attributes.get("telephone", [None])[0],
                    "fonction": attributes.get("fonction", [None])[0],
                    "created_timestamp": user_data.get("createdTimestamp")
                }

                # Fetch roles if requested
                if include_roles:
                    # Get realm roles
                    realm_roles_response = await client.get(
                        f"{KEYCLOAK_CONFIG['server_url']}/admin/realms/{KEYCLOAK_CONFIG['realm']}/users/{user_id}/role-mappings/realm",
                        headers={
                            "Authorization": f"Bearer {admin_token}"
                        }
                    )

                    if realm_roles_response.status_code == 200:
                        realm_roles = realm_roles_response.json()
                        role_names = [role.get("name") for role in realm_roles]
                        user["realm_roles"] = role_names
                    else:
                        user["realm_roles"] = []
                        logger.warning(f"Failed to get realm roles for user {user_id}: {realm_roles_response.text}")

                    # Get client roles
                    clients_response = await client.get(
                        f"{KEYCLOAK_CONFIG['server_url']}/admin/realms/{KEYCLOAK_CONFIG['realm']}/clients",
                        headers={
                            "Authorization": f"Bearer {admin_token}"
                        }
                    )

                    if clients_response.status_code == 200:
                        clients = clients_response.json()
                        client_roles = {}

                        for client_data in clients:
                            client_id = client_data.get("id")
                            client_name = client_data.get("clientId")

                            client_roles_response = await client.get(
                                f"{KEYCLOAK_CONFIG['server_url']}/admin/realms/{KEYCLOAK_CONFIG['realm']}/users/{user_id}/role-mappings/clients/{client_id}",
                                headers={
                                    "Authorization": f"Bearer {admin_token}"
                                }
                            )

                            if client_roles_response.status_code == 200:
                                roles = client_roles_response.json()
                                if roles:
                                    client_roles[client_name] = [role.get("name") for role in roles]

                        if client_roles:
                            user["client_roles"] = client_roles

                users.append(user)

            return {
                "users": users,
                "pagination": {
                    "first": first_result,
                    "max": max_results,
                    "count": len(users)
                }
            }

    except httpx.RequestError as e:
        logger.error(f"Error connecting to Keycloak: {str(e)}")
        raise HTTPException(
            status_code=503,
            detail=str(e)
        )


@router.post("/sync", status_code=201)
async def sync_users_to_db(
        request: Request,
        db: AsyncSession = Depends(get_db),
        user: dict = Depends(require_roles(["admin"]))
):
    """
    Synchronise tous les utilisateurs depuis Keycloak vers la base de données locale.
    """
    # Obtenir le token admin
    admin_token = await get_master_admin_token()

    # Récupérer tous les utilisateurs de Keycloak
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Récupération des utilisateurs avec pagination
            first_result = 0
            max_results = 100
            all_keycloak_users = []

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
                    raise HTTPException(
                        status_code=response.status_code,
                        detail=response.text
                    )

                batch = response.json()
                if not batch:
                    break

                all_keycloak_users.extend(batch)
                first_result += max_results

                if len(batch) < max_results:
                    break

            # Suite de la fonction... (le reste du code reste le même)
            # [Code de synchronisation des utilisateurs]

            # Récupérer tous les utilisateurs existants dans la BD locale
            local_users = await user_repo.get_utilisateurs(db, skip=0, limit=100000)
            local_user_map = {str(user.id): user for user in local_users}

            # Tenir le compte des différentes opérations
            created_count = 0
            updated_count = 0
            deactivated_count = 0

            # Traiter chaque utilisateur Keycloak
            for kc_user in all_keycloak_users:
                kc_user_id = kc_user.get("id")
                attributes = kc_user.get("attributes", {})

                # Récupérer TOUS les rôles pour cet utilisateur (realm et client)
                all_roles = []

                # Rôles du realm
                roles_response = await client.get(
                    f"{KEYCLOAK_CONFIG['server_url']}/admin/realms/{KEYCLOAK_CONFIG['realm']}/users/{kc_user_id}/role-mappings/realm",
                    headers={
                        "Authorization": f"Bearer {admin_token}"
                    }
                )

                if roles_response.status_code == 200:
                    realm_roles = roles_response.json()
                    realm_role_names = [role.get("name") for role in realm_roles]
                    all_roles.extend(realm_role_names)

                # Rôles des clients
                clients_response = await client.get(
                    f"{KEYCLOAK_CONFIG['server_url']}/admin/realms/{KEYCLOAK_CONFIG['realm']}/clients",
                    headers={
                        "Authorization": f"Bearer {admin_token}"
                    }
                )

                if clients_response.status_code == 200:
                    clients = clients_response.json()

                    for client_data in clients:
                        client_id = client_data.get("id")
                        client_name = client_data.get("clientId")

                        client_roles_response = await client.get(
                            f"{KEYCLOAK_CONFIG['server_url']}/admin/realms/{KEYCLOAK_CONFIG['realm']}/users/{kc_user_id}/role-mappings/clients/{client_id}",
                            headers={
                                "Authorization": f"Bearer {admin_token}"
                            }
                        )

                        if client_roles_response.status_code == 200:
                            client_roles = client_roles_response.json()
                            for role in client_roles:
                                all_roles.append(f"{client_name}:{role.get('name')}")

                # Convertir tous les rôles en une chaîne unique séparée par des virgules
                roles_string = ",".join(all_roles) if all_roles else "user"

                # Créer un modèle utilisateur pour l'insertion/mise à jour
                user_data = {
                    "prenom": kc_user.get("firstName", ""),
                    "nom": kc_user.get("lastName", ""),
                    "email": kc_user.get("email", ""),
                    "username": kc_user.get("username", ""),
                    "fonction": attributes.get("fonction", ["Autre"])[0] if attributes.get("fonction") else "Autre",
                    "statut": "Active" if kc_user.get("enabled", True) else "Inactive",
                    "role": roles_string,
                    "unite": attributes.get("unite", ["Autre"])[0] if attributes.get("unite") else "Autre",
                    "telephone": attributes.get("telephone", [None])[0] if attributes.get("telephone") else None
                }

                # Vérifier si l'utilisateur existe déjà par ID
                if kc_user_id in local_user_map:
                    # Mettre à jour l'utilisateur existant
                    existing_user = local_user_map[kc_user_id]
                    for key, value in user_data.items():
                        setattr(existing_user, key, value)

                    existing_user.updatedAt = datetime.now()
                    await db.commit()
                    updated_count += 1
                else:
                    # Créer un nouvel utilisateur
                    try:
                        new_user = Utilisateur(
                            id=uuid.UUID(kc_user_id),
                            dateInscription=datetime.now(),
                            updatedAt=datetime.now(),
                            **user_data
                        )
                        db.add(new_user)
                        await db.commit()
                        created_count += 1
                    except Exception as e:
                        logger.error(f"Error creating user {kc_user.get('username')}: {str(e)}")
                        await db.rollback()

            # Marquer comme inactifs les utilisateurs qui sont dans la BD locale mais pas dans Keycloak
            keycloak_user_ids = set(kc_user.get("id") for kc_user in all_keycloak_users)
            for local_id, local_user in local_user_map.items():
                if local_id not in keycloak_user_ids and local_user.statut != "Inactive":
                    local_user.statut = "Inactive"
                    local_user.updatedAt = datetime.now()
                    await db.commit()
                    deactivated_count += 1

            return {
                "success": True,
                "message": "User synchronization completed",
                "stats": {
                    "total_keycloak_users": len(all_keycloak_users),
                    "total_local_users": len(local_users),
                    "created": created_count,
                    "updated": updated_count,
                    "deactivated": deactivated_count
                }
            }

    except Exception as e:
        logger.error(f"Error syncing users: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error syncing users: {str(e)}"
        )