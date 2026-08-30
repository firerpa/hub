# Copyright 2025 rev1si0n (ihaven0emmail@gmail.com). All rights reserved.
# encoding=utf8
from apscheduler.triggers.cron import CronTrigger
from apscheduler.schedulers.blocking import BlockingScheduler

from .models import Job, JobMode, JobState, session_scope
from .handlers.event import issue_task_by_job


def handle_crontab(job_id):
    issue_task_by_job.apply_async(args=[job_id])


def upsert_job(scheduler, job):
    trigger = CronTrigger.from_crontab(job.crontab)
    scheduler.add_job(func=handle_crontab, trigger=trigger, args=[job.id], id=str(job.id),
                                            replace_existing=True, max_instances=1,
                                            coalesce=True, misfire_grace_time=30)

def load_running_crontab_jobs():
    with session_scope() as session:
        return session.query(Job).filter(Job.mode == JobMode.CRONTAB.value,
                                 Job.state == JobState.RUNNING.value).all()


def upsert_jobs(scheduler, jobs):
    list(map(lambda job: upsert_job(scheduler, job), jobs))


def remove_stale_jobs(scheduler, wanted):
    current = {job.id for job in scheduler.get_jobs()}
    list(map(scheduler.remove_job, (current - (wanted | set(["cron"])))))


def sync_crontab_jobs(scheduler):
    jobs = load_running_crontab_jobs()
    remove_stale_jobs(scheduler, set(str(j.id) for j in jobs))
    upsert_jobs(scheduler, jobs)


if __name__ == "__main__":
    scheduler = BlockingScheduler()
    scheduler.add_job(sync_crontab_jobs, "interval", seconds=10, args=[scheduler],
                                            id="cron", replace_existing=True)
    scheduler.start()