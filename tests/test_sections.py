from app.engine import parse_sections, parse_csv

def test_sections():
    s=parse_sections("### Assessment\nReview\n### Validation\nRescan")
    assert [x["title"] for x in s]==["Assessment", "Validation"]

def test_sample():
    from pathlib import Path
    f=parse_csv(Path("samples/public_cve_lab.csv").read_bytes())
    assert len(f)==2 and f[0]["cve"]=="CVE-2021-44228"
