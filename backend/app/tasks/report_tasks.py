import uuid


async def generate_report_task(scan_id: uuid.UUID | str) -> None:
    """Task boundary retained for a future non-callback report workflow."""
    # TODO: Report generation task ownership depends on the final LLM job contract.
    _ = scan_id

