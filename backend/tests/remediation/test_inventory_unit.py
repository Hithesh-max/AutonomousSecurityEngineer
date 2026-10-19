"""Pure unit tests for project-wide inventory; no database/network required."""
from types import SimpleNamespace
from uuid import uuid4
from unittest.mock import patch

from app.api.remediation import remediation_inventory
from app.remediation.source import SourceUnavailable


class Query:
    def __init__(self, records):
        self.records = records
    def join(self, *args, **kwargs): return self
    def filter(self, *args, **kwargs): return self
    def order_by(self, *args, **kwargs): return self
    def first(self): return self.records[0] if self.records else None
    def all(self): return self.records


class FakeDB:
    def __init__(self, repo, findings, patches, analyses):
        self.collections = [repo, findings, patches, analyses]
        self.index = 0
    def query(self, *args):
        result = Query(self.collections[self.index])
        self.index += 1
        return result


def test_inventory_reports_unsupported_without_claiming_fix():
    repo_id, user_id, scan_id = uuid4(), uuid4(), uuid4()
    f1, f2 = uuid4(), uuid4()
    repo = SimpleNamespace(id=repo_id, latest_analysis_job_id=scan_id)
    findings = [SimpleNamespace(id=f1, title='SQL injection', severity='HIGH', source='SAST',
                                source_location={'file':'app.py'}),
                SimpleNamespace(id=f2, title='Hardcoded secret', severity='HIGH', source='SECRET_DETECTION',
                                source_location={'file':'settings.py'})]
    patch_record = SimpleNamespace(id=uuid4(), finding_id=f1, status='APPROVED',
                                   patch_sha256='a'*64, verification_status='NOT_VERIFIED')
    analysis_record = SimpleNamespace(finding_id=f1, status='COMPLETED')
    db = FakeDB([repo], findings, [patch_record], [analysis_record])
    def locate_for(finding):
        if finding.id == f2:
            raise SourceUnavailable('SOURCE_UNAVAILABLE', 'Secret cannot be patched automatically')
        return SimpleNamespace(path='app.py')
    with patch('app.api.remediation.locator_for') as mocked:
        mocked.return_value.locate.side_effect = lambda db, finding, user: locate_for(finding)
        result = remediation_inventory(repo_id, db, SimpleNamespace(id=user_id))
    assert result['total'] == 2
    assert result['eligible'] == 1
    assert result['unsupported'] == 1
    assert result['approved'] == 1
    assert result['items'][0]['verification_status'] == 'NOT_VERIFIED'
    assert result['items'][1]['eligible'] is False
    assert 'Secret cannot' in result['items'][1]['reason']
