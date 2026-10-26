from app.engine import normalize_report, advise

def test_report_validation():
    r = normalize_report({'assessment':'Test', 'recommended_actions':['Verify version'], 'validation_steps':['Rescan'], 'uncertainty':'Unknown'}, 'Fallback')
    assert r['assessment'] == 'Test'
    assert r['recommended_actions'] == ['Verify version']
    assert r['validation_steps'] == ['Rescan']

def test_malformed_fields_do_not_crash():
    r = normalize_report({'assessment': [], 'recommended_actions':'not a list', 'validation_steps':[123, 'Rescan']}, 'Verify')
    assert r['recommended_actions'] == ['Verify']
    assert r['validation_steps'] == ['Rescan']

def test_demo_fallback_is_structured():
    f={'host':'lab','name':'Sample','risk':'high','cve':'','priority_score':60,'score_breakdown':{'severity':60,'epss':0,'kev':0},'evidence':[],'enrichment_status':'demo','solution':'Check patch'}
    r=advise(f,False)
    assert r['report']['recommended_actions']==['Check patch']
