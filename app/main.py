import os
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse
from .engine import parse_csv, analyze

app = FastAPI(title='VulnAgent AI', version='1.2.0')

@app.get('/health')
def health():
    return {'status': 'ok', 'mistral_configured': bool(os.getenv('MISTRAL_API_KEY'))}

@app.post('/analyze')
async def run(file: UploadFile = File(...), mode: str = 'demo'):
    if mode not in ('demo', 'live'):
        raise HTTPException(400, 'mode must be demo or live')
    try:
        findings = parse_csv(await file.read(2_000_001))
    except (ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(400, str(exc))
    if not findings:
        raise HTTPException(400, 'No findings')
    s = analyze(findings, mode)
    return {'count': len(findings), 'ranked': s['ranked'], 'recommendations': s['recommendations'], 'trace': s['trace'], 'read_only': True}

@app.get('/', response_class=HTMLResponse)
def home():
    from pathlib import Path
    return (Path(__file__).parent / 'dashboard.html').read_text(encoding='utf-8')
