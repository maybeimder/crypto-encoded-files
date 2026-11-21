import os
from typing import Annotated

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Path, Request, Response, status
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from cryptostore.server.object_store import MAXIMUM_BLOCK_PAYLOAD, ObjectStore, StoreError
from cryptostore.server.session_tokens import SessionTokens

FileId = Annotated[str, Path(pattern=r"^[0-9a-f]{32}$")]
UserId = Annotated[str, Path(pattern=r"^[0-9a-f]{64}$")]
Version = Annotated[int, Path(ge=1)]
BlockIndex = Annotated[int, Path(ge=0)]


# Ningún endpoint recibe claves privadas ni texto claro: solo identidades públicas,
# bloques cifrados, manifiestos firmados y envolventes selladas
def create_app(data_directory: str) -> FastAPI:
    store = ObjectStore(data_directory)
    session_tokens = SessionTokens(os.path.join(data_directory, "tokens.json"))
    app = FastAPI(title="Almacenamiento cifrado y compartición de archivos")

    @app.exception_handler(StoreError)
    def translate_store_error(_request: Request, error: StoreError):
        return JSONResponse(status_code=error.http_status, content={"detail": str(error)})

    def authenticated_user(authorization: str | None = Header(default=None)) -> str:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "falta el token de sesión")
        user_id = session_tokens.user_for(authorization.removeprefix("Bearer "))
        if user_id is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "token de sesión inválido")
        return user_id

    # ---------- usuarios ----------

    @app.post("/users", status_code=status.HTTP_201_CREATED)
    def register_user(identity: dict = Body(...)):
        user_id = store.register_user(identity)
        return {"user_id": user_id, "token": session_tokens.issue(user_id)}

    @app.get("/users")
    def list_users(_caller: str = Depends(authenticated_user)):
        return store.list_users()

    @app.get("/users/{user_id}")
    def get_user(user_id: UserId, _caller: str = Depends(authenticated_user)):
        return store.get_user(user_id)

    # ---------- archivos ----------

    @app.get("/files")
    def list_files(caller: str = Depends(authenticated_user)):
        return store.list_files(caller)

    @app.put("/files/{file_id}/versions/{version}/blocks/{index}", status_code=status.HTTP_204_NO_CONTENT)
    async def put_block(request: Request, file_id: FileId, version: Version,
                        index: BlockIndex, caller: str = Depends(authenticated_user)):
        payload = await _read_body_with_limit(request, MAXIMUM_BLOCK_PAYLOAD)
        await run_in_threadpool(store.put_block, caller, file_id, version, index, payload)

    @app.get("/files/{file_id}/versions/{version}/blocks")
    def list_uploaded_blocks(file_id: FileId, version: Version,
                             caller: str = Depends(authenticated_user)):
        return store.list_uploaded_blocks(caller, file_id, version)

    @app.get("/files/{file_id}/versions/{version}/blocks/{index}")
    def get_block(file_id: FileId, version: Version, index: BlockIndex,
                  caller: str = Depends(authenticated_user)):
        return Response(store.get_block(caller, file_id, version, index), media_type="application/octet-stream")

    @app.put("/files/{file_id}/versions/{version}/manifest", status_code=status.HTTP_204_NO_CONTENT)
    def commit_manifest(file_id: FileId, version: Version, manifest: dict = Body(...),
                        caller: str = Depends(authenticated_user)):
        store.commit_manifest(caller, file_id, version, manifest)

    @app.get("/files/{file_id}/manifest")
    def get_latest_manifest(file_id: FileId, caller: str = Depends(authenticated_user)):
        return store.get_manifest(caller, file_id)

    @app.get("/files/{file_id}/versions/{version}/manifest")
    def get_manifest(file_id: FileId, version: Version,
                     caller: str = Depends(authenticated_user)):
        return store.get_manifest(caller, file_id, version)

    # ---------- envolventes ----------

    @app.get("/files/{file_id}/grants")
    def list_grants(file_id: FileId, caller: str = Depends(authenticated_user)):
        return store.list_grant_recipients(caller, file_id)

    @app.get("/files/{file_id}/grants/mine")
    def get_my_grant(file_id: FileId, caller: str = Depends(authenticated_user)):
        return store.get_own_grant(caller, file_id)

    @app.put("/files/{file_id}/grants/{recipient_id}")
    def put_grant(file_id: FileId, recipient_id: UserId, grant: dict = Body(...),
                  caller: str = Depends(authenticated_user)):
        return {"acl_epoch": store.put_grant(caller, file_id, recipient_id, grant)}

    @app.delete("/files/{file_id}/grants/{recipient_id}")
    def delete_grant(file_id: FileId, recipient_id: UserId,
                     caller: str = Depends(authenticated_user)):
        return {"acl_epoch": store.delete_grant(caller, file_id, recipient_id)}

    return app


async def _read_body_with_limit(request: Request, maximum_bytes: int) -> bytes:
    received = bytearray()
    async for chunk in request.stream():
        received.extend(chunk)
        # Corta apenas supera el límite, sin acumular el exceso en memoria
        if len(received) > maximum_bytes:
            raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, "bloque demasiado grande")
    return bytes(received)

