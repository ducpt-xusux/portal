"""Additive output contracts; intentionally separate from frozen v4.1 views."""
from typing import Literal
from pydantic import Field
from ..dashboard_funnel import EvaluationRun
from .models import (Closed, Count, Seconds, Partition, Recovery, Backup, Resilience, Tls, Privacy,
    Staging, P19, CaseObservation, CorrelationObservation)


class EvaluationPanel(Closed):
    schema_version: Literal['n91-evaluation-panel-1']
    run: EvaluationRun
    expected_partitions: dict[Partition,Count]
    observed_partitions: dict[Partition,Count]
    expected_correlations: Literal[13]
    observed_correlations: Count
    catalog_basis: Literal['DESIGN_ONLY']
    catalog_flag: Literal['NOT_RUN']
    cases: list[CaseObservation]
    correlations: list[CorrelationObservation]


class RecoveryDetail(Recovery):
    lab_rto_seconds: Seconds | None
    lab_rto_reason: Literal['TIMING_NOT_COMPARABLE_OR_MISSING'] | None
    metric_semantics: Literal['LAB_BACKUP_GAP_AND_FAULT_TO_VERIFIED_QUERY_NOT_PRODUCTION']
    unit: Literal['seconds']
    lost_marker_count: Count | None
    current_verification: Literal['CURRENT_NOT_VERIFIED','SCOPED_OBSERVATION']
    production_measurement: Literal['NOT_MEASURED']


class SystemPanel(Closed):
    schema_version: Literal['n91-system-panel-1']
    kind: Literal['backups','recoveries','resilience','tls','privacy','staging','p19']
    items: list[Backup | RecoveryDetail | Resilience | Tls | Privacy | Staging | P19] = Field(min_length=1,max_length=100)
    scope_note: Literal['Imported frozen observations; source mode and context remain per item.']
