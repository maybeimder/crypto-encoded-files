import threading
import uuid
from dataclasses import dataclass, field
from typing import Callable

from cryptostore.client.server_api import ServerError
from cryptostore.errors import CryptoStoreError, VerificationError

ProgressCallback = Callable[[int, int], None]


@dataclass
class Job:
    job_id: str
    kind: str
    owner_username: str
    status: str = "running"  # running | done | rejected | failed
    completed_steps: int = 0
    total_steps: int = 0
    message: str = ""
    result: dict = field(default_factory=dict)

    def to_json_dict(self) -> dict:
        return {"job_id": self.job_id, "kind": self.kind, "status": self.status, "message": self.message,
                "completed_steps": self.completed_steps, "total_steps": self.total_steps,
                # Lo que empieza por "_" es interno (rutas locales) y no se envía al navegador
                "result": {key: value for key, value in self.result.items() if not key.startswith("_")}}


# Subidas y descargas largas corren en segundo plano; el navegador consulta su progreso
class JobRegistry:
    def __init__(self):
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def start(self, kind: str, owner_username: str, work: Callable[[ProgressCallback], dict]) -> Job:
        job = Job(job_id=uuid.uuid4().hex, kind=kind, owner_username=owner_username)
        with self._lock:
            self._jobs[job.job_id] = job
        threading.Thread(target=self._run, args=(job, work), daemon=True).start()
        return job

    def get(self, job_id: str, owner_username: str) -> Job | None:
        with self._lock:
            job = self._jobs.get(job_id)
        # Un usuario nunca ve ni recoge las tareas (ni los archivos descifrados) de otro
        return job if job is not None and job.owner_username == owner_username else None

    def _run(self, job: Job, work: Callable[[ProgressCallback], dict]) -> None:
        def report_progress(completed_steps: int, total_steps: int) -> None:
            job.completed_steps, job.total_steps = completed_steps, total_steps
        try:
            job.result = work(report_progress)
            job.status = "done"
        except VerificationError as error:
            # Igual que en la terminal: un rechazo criptográfico se distingue de un error común
            job.status, job.message = "rejected", str(error)
        except (CryptoStoreError, ServerError, OSError) as error:
            job.status, job.message = "failed", str(error)
