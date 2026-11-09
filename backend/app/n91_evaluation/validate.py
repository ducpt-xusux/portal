"""Read-only local validation CLI. Prints finite metadata, never source content."""
import argparse
import json
from pathlib import Path
from types import SimpleNamespace
from .service import EvaluationSystemService
from .sources import SourceConfig, SourceError, evaluation_source, system_source
from ..evidence_registry import EvidenceConfig, EvidenceRegistry, EvidenceError


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context',choices=['TEST','EVALUATION','LIVE'],default='EVALUATION')
    parser.add_argument('--evaluations',type=Path)
    parser.add_argument('--evaluations-sha256')
    parser.add_argument('--run-index',type=Path)
    parser.add_argument('--system',type=Path)
    parser.add_argument('--system-sha256')
    parser.add_argument('--evidence-index',type=Path,required=True)
    args=parser.parse_args()
    service=EvaluationSystemService(
        evaluations=evaluation_source(SourceConfig(args.evaluations,args.evaluations_sha256,args.context)),
        system=system_source(SourceConfig(args.system,args.system_sha256,args.context)),
        evidence=EvidenceRegistry(EvidenceConfig(args.evidence_index)))
    try:
        result=dict(context=args.context,source_acceptance='NORMALIZED_METADATA_ONLY',evaluations=None,system=None)
        if args.evaluations:
            document,sha=service.evaluations.read()
            request=SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(settings=SimpleNamespace(evaluation_index_path=args.run_index))))
            for run_id in document.run_hashes:
                service.evaluation(request,run_id)
            result['evaluations']=dict(sha256=sha,runs=len(document.run_hashes),case_records=len(document.cases),correlation_records=len(document.correlations))
        if args.system:
            document,sha=service.system.read()
            rows=document.backups+document.recoveries+document.resilience+document.tls+document.privacy+document.staging+([document.p19] if document.p19 else [])
            service.links(rows)
            result['system']=dict(sha256=sha,observation_records=len(rows))
        if not args.evaluations and not args.system:
            raise SourceError('EVALUATION_SYSTEM_SOURCE_NOT_CONFIGURED')
        print(json.dumps(dict(status='VALID_NORMALIZED_SNAPSHOT',**result)))
        return 0
    except (SourceError,EvidenceError) as exc:
        print(json.dumps(dict(status='UNAVAILABLE',code=exc.code)))
        return 2
    except (OSError,ValueError,TypeError,AttributeError):
        print(json.dumps(dict(status='UNAVAILABLE',code='EVALUATION_SYSTEM_VALIDATION_FAILED')))
        return 2


if __name__=='__main__':
    raise SystemExit(main())
