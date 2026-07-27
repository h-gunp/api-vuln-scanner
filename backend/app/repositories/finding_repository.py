import uuid
from dataclasses import dataclass

from sqlalchemy import case, delete, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import SEVERITY_RANK, Severity
from app.models.finding import Finding
from app.models.operation import Operation


@dataclass(frozen=True)
class FindingPage:
    rows: list[tuple[Finding, Operation]]
    total: int


class FindingRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def replace_for_scan(
        self,
        scan_id: uuid.UUID,
        findings: list[Finding],
    ) -> list[Finding]:
        await self.session.execute(delete(Finding).where(Finding.scan_id == scan_id))
        self.session.add_all(findings)
        await self.session.flush()
        return findings

    async def get_with_operation(self, finding_id: str) -> tuple[Finding, Operation] | None:
        statement = (
            select(Finding, Operation)
            .join(Operation, Finding.operation_pk == Operation.id)
            .where(Finding.id == finding_id)
        )
        row = (await self.session.execute(statement)).one_or_none()
        return (row[0], row[1]) if row else None

    async def list_for_scan(
        self,
        scan_id: uuid.UUID,
        *,
        q: str | None,
        module_id: str | None,
        severity: Severity | None,
        page: int,
        size: int,
        descending: bool,
    ) -> FindingPage:
        predicates = [Finding.scan_id == scan_id]
        if module_id:
            predicates.append(Finding.module_id == module_id)
        if severity:
            predicates.append(Finding.severity == severity)
        if q:
            pattern = f"%{q}%"
            predicates.append(
                or_(
                    Finding.id.ilike(pattern),
                    Finding.module_id.ilike(pattern),
                    Operation.method.ilike(pattern),
                    Operation.path_template.ilike(pattern),
                    Finding.summary.ilike(pattern),
                )
            )

        rank = case(
            {severity.value: score for severity, score in SEVERITY_RANK.items()},
            value=Finding.severity,
            else_=0,
        )
        ordering = rank.desc() if descending else rank.asc()
        statement = (
            select(Finding, Operation)
            .join(Operation, Finding.operation_pk == Operation.id)
            .where(*predicates)
            .order_by(ordering, Finding.created_at.desc(), Finding.id)
            .offset((page - 1) * size)
            .limit(size)
        )
        rows = (await self.session.execute(statement)).all()
        total_statement = (
            select(func.count(Finding.id))
            .select_from(Finding)
            .join(Operation, Finding.operation_pk == Operation.id)
            .where(*predicates)
        )
        total = int((await self.session.scalar(total_statement)) or 0)
        return FindingPage(rows=[(row[0], row[1]) for row in rows], total=total)

    async def existing_global_ids(self, finding_ids: set[str]) -> set[str]:
        if not finding_ids:
            return set()
        result = await self.session.scalars(select(Finding.id).where(Finding.id.in_(finding_ids)))
        return set(result)

    async def list_models_for_scan(self, scan_id: uuid.UUID) -> list[Finding]:
        result = await self.session.scalars(
            select(Finding).where(Finding.scan_id == scan_id)
        )
        return list(result)
