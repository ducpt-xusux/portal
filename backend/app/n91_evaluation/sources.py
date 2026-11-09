"""Operator-configured, bounded immutable local sources; reuse EvidenceRegistry IO."""
from dataclasses import dataclass
from pathlib import Path
from .models import EvaluationObservations, SystemObservations
from ..evidence_registry import EvidenceError, read_bytes, load_model, digest, MAX_JSON


class SourceError(Exception):
    def __init__(self, code, status=503):
        self.code, self.status = code, status
        super().__init__(code)


@dataclass(frozen=True)
class SourceConfig:
    path: Path | None = None
    sha256: str | None = None
    context: str = 'EVALUATION'


class JsonSource:
    def __init__(self, config, model):
        self.config, self.model = config, model

    def read(self):
        if self.config.path is None:
            raise SourceError('EVALUATION_SYSTEM_SOURCE_NOT_CONFIGURED')
        if self.config.context not in {'TEST','EVALUATION','LIVE'} or not self.config.sha256:
            raise SourceError('EVALUATION_SYSTEM_SOURCE_PIN_REQUIRED')
        try:
            raw = read_bytes(self.config.path, MAX_JSON)
            sha = digest(raw)
            if sha != self.config.sha256:
                raise SourceError('EVALUATION_SYSTEM_HASH_MISMATCH')
            value = load_model(raw, self.model)
            rows = (value.cases + value.correlations if isinstance(value, EvaluationObservations) else
                value.backups + value.recoveries + value.resilience + value.tls + value.privacy + value.staging + ([value.p19] if value.p19 else []))
            if any(row.scope.context != self.config.context for row in rows):
                raise SourceError('EVALUATION_SYSTEM_CONTEXT_MISMATCH')
            return value, sha
        except EvidenceError as exc:
            raise SourceError('EVALUATION_SYSTEM_' + exc.code.removeprefix('EVIDENCE_')) from None
        except TimeoutError:
            raise SourceError('EVALUATION_SYSTEM_SOURCE_TIMEOUT',504) from None
        except (OSError, ValueError, RuntimeError):
            raise SourceError('EVALUATION_SYSTEM_SOURCE_UNAVAILABLE') from None


def evaluation_source(config=SourceConfig()):
    return JsonSource(config, EvaluationObservations)


def system_source(config=SourceConfig()):
    return JsonSource(config, SystemObservations)
