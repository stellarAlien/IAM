"""Summarize client observations, not an authoritative server audit trail."""

from collections import Counter
from datetime import datetime
import json
from pathlib import Path
import sys


def summarize(path):
    counts = Counter()
    denials = 0
    exposures = 0
    canary_reads = 0
    contained_at = None
    exposure_at = None
    for line in path.read_text().splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict) or record.get('source') != 'exercise-client-observation':
            continue
        actor, outcome = record.get('actor'), record.get('outcome')
        if actor not in ('alice', 'bob', 'eve', 'facilitator') or outcome not in (
            'allowed', 'denied', 'authenticated', 'baseline-restored',
            'payment-read-overgrant-enabled', 'eve-group-access-revoked',
            'contained-and-workload-secrets-rotated',
        ):
            continue
        counts[(actor, outcome)] += 1
        if actor == 'eve':
            denials += outcome == 'denied'
            canary_reads += outcome == 'allowed' and record.get('action') == 'canary'
            if outcome == 'allowed' and record.get('action') in ('payment', 'watch-payment'):
                exposures += 1
                exposure_at = exposure_at or record.get('timestamp')
        if outcome in ('baseline-restored', 'payment-read-overgrant-enabled'):
            exposure_at = None
            contained_at = None
        if outcome in ('eve-group-access-revoked', 'contained-and-workload-secrets-rotated') and exposure_at:
            contained_at = record.get('timestamp')
    print('CLIENT OBSERVATIONS ONLY — corroborate with Conjur audit logs before incident conclusions.')
    for (actor, outcome), count in sorted(counts.items()):
        print(f'{actor:12} {outcome:40} {count}')
    print(f'Eve denied attempts: {denials}; synthetic canary reads: {canary_reads}; observed payment reads: {exposures}')
    if exposure_at and contained_at:
        try:
            seconds = (datetime.fromisoformat(contained_at) - datetime.fromisoformat(exposure_at)).total_seconds()
        except (ValueError, TypeError):
            return
        if seconds >= 0:
            print(f'Latest observed exposure-to-containment-command interval: {seconds:.1f}s (not verified end-to-end MTTR).')


if __name__ == '__main__':
    path = Path('.runtime/evidence/events.jsonl')
    if not path.exists():
        print('No exercise observations yet; run make exercise-init and make act.', file=sys.stderr)
        sys.exit(1)
    summarize(path)
