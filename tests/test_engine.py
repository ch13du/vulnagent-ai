from pathlib import Path
from app.engine import parse_csv, analyze

def test_demo():
    rows=parse_csv(Path('samples/nessus_demo.csv').read_bytes())
    result=analyze(rows)
    assert len(result['ranked'])==2
    assert result['ranked'][0]['risk']=='high'
    assert all(x['approval_required'] for x in result['recommendations'])

def test_reject_invalid_severity():
    import pytest
    with pytest.raises(ValueError):parse_csv(b'Host,Name,Risk\na,b,unknown\n')

def test_no_fabricated_cve():
    assert parse_csv(b'Host,Name,Risk,CVE\na,b,High,wrong\n')[0]['cve']==''
