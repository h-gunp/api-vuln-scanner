from dataclasses import dataclass


@dataclass(frozen=True)
class ExternalSubmission:
    external_job_id: str

