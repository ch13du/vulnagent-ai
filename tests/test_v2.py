from app.engine import enrich, rank, advise, parse_csv

def test_no_external_calls_in_demo():
    rows = parse_csv(b'Host,Name,Risk,CVE\nlab,Example,High,CVE-2024-0001\n')
    result = enrich({'findings': rows, 'mode': 'demo'})
    assert result['enriched'][0]['kev'] is None
    assert result['enriched'][0]['evidence'] == []

def test_deterministic_score_with_kev():
    f = {'risk':'high','epss':0.5,'kev':True}
    result = rank({'enriched':[f]})['ranked'][0]
    assert result['priority_score'] == 90
    assert result['score_breakdown'] == {'severity':60,'epss':10,'kev':20}

def test_invalid_cve_not_evidence():
    rows = parse_csv(b'Host,Name,Risk,CVE\nlab,Example,High,CVE-NOT-REAL\n')
    assert rows[0]['cve'] == ''

def test_fallback_requires_approval(monkeypatch):
    monkeypatch.delenv('MISTRAL_API_KEY', raising=False)
    f={'host':'lab','name':'test','risk':'high','cve':'','priority_score':60,'score_breakdown':{'severity':60,'epss':0,'kev':0},'evidence':[],'enrichment_status':'not requested','solution':''}
    result=advise(f, True)
    assert result['approval_required'] is True
    assert result['generated_by']=='deterministic fallback'
