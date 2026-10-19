"""Guards the existing bundled-lab source mapping: the new locator must agree with the untouched /lab-source endpoint."""
import pytest

from app.api import web_scans
from app.remediation.source import BundledLabLocator
from tests.remediation.helpers import make_finding

CASES = [("40012", "/echo", "text"), ("40018", "/search", "q"), ("10038", "/", ""), ("10020", "/", ""),
         ("10021", "/echo", ""), ("10010", "/", ""), ("10054", "/search", ""), ("10036", "/", "")]


def test_every_mapped_rule_is_covered_by_this_test():
    assert {c[0] for c in CASES} == set(web_scans._LAB_MAPPINGS)


@pytest.mark.parametrize("rule,path,param", CASES)
def test_locator_matches_existing_endpoint(client, test_db, test_user, auth, rule, path, param):
    f = make_finding(test_db, test_user, rule=rule, path="http://ase-lab:8080" + path, param=param)
    existing = client.get(f"/api/web-scans/{f.scan_id}/findings/{f.id}/lab-source", headers=auth)
    assert existing.status_code == 200, existing.text
    old = existing.json()
    new = BundledLabLocator().locate(test_db, f, test_user.id)
    assert (new.start_line, new.end_line, new.highlight_line, new.sha256, new.path) == (
        old["start_line"], old["end_line"], old["highlight_line"], old["sha256"], old["path"])
    assert new.window_text(with_numbers=False) == old["content"]


def test_locator_denies_other_users_scan(test_db, test_user, test_user_2):
    from app.remediation.source import SourceUnavailable
    f = make_finding(test_db, test_user)
    with pytest.raises(SourceUnavailable):
        BundledLabLocator().locate(test_db, f, test_user_2.id)
