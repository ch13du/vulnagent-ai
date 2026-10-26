from fastapi.testclient import TestClient
from app.main import app
client=TestClient(app)
def test_health():
    assert client.get('/health').json()['status']=='ok'
def test_analysis():
    csv_data=b'Host,Name,Risk,CVE,Description,Solution\nserver1,Sample issue,High,CVE-2024-0001,Test finding,Apply vendor patch\n'
    r=client.post('/analyze?mode=demo',files={'file':('scan.csv',csv_data,'text/csv')})
    assert r.status_code==200
    assert r.json()['count']==1
    assert r.json()['recommendations'][0]['approval_required'] is True
