import json

from cryptostore.benchmarks.__main__ import main


def test_quick_benchmark_writes_report(tmp_path):
    assert main(["--quick", "--repetitions", "1", "--output-dir", str(tmp_path)]) == 0
    results = json.loads((tmp_path / "mediciones.json").read_text())
    # Las envolventes crecen 80 bytes por destinatario, sin importar el tamaño del archivo
    assert [row["grant_raw_bytes"] for row in results["grant_growth"]] == [80, 160, 240, 320, 400] * 2
    assert all(row["overhead_percent"] < 1 for row in results["block_size_overhead"])
    assert "## Crecimiento de las envolventes" in (tmp_path / "mediciones.md").read_text()
