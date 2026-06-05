"""NetMind AI async worker.

Celery application that runs the PCAP analysis pipeline
(parsing -> feature extraction -> rule detection -> AI assessment)
in background workers.
"""

from celery import Celery

from backend.config import get_settings

settings = get_settings()

celery_app = Celery(
    "netmind",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)

celery_app.conf.update(
    task_acks_late=settings.celery_task_acks_late,
    task_time_limit=settings.celery_task_time_limit_sec,
    task_soft_time_limit=settings.celery_task_soft_time_limit_sec,
    task_track_started=True,
    worker_prefetch_multiplier=1,
    broker_connection_retry_on_startup=True,
    beat_schedule={
        "cleanup-expired-pcaps": {
            "task": "cleanup_expired_pcaps",
            "schedule": settings.storage_cleanup_schedule_seconds,
            "args": (),
        }
    },
)

# Auto-discover tasks in the tasks package
celery_app.autodiscover_tasks(["backend.worker.tasks"])
