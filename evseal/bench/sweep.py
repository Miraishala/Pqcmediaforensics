"""Benchmark parameter sweep (SPEC §6 item 8, SPEC §7F).

Measures:
- Throughput (MB/s and real-time multiplier)
- Wall time and CPU time (process time)
- Storage overhead %
- Peak memory usage
across §4 parameter configurations (algorithm, block size, EC k/m, workers).
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
import tracemalloc
from pathlib import Path

from evseal.bench.synth import make_media
from evseal.core import profile as prof
from evseal.core.seal import seal_path
from evseal.core.verify import verify
from evseal.workspace import Workspace

try:
    import resource

    def _peak_rss_mb() -> float:
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0
except ImportError:
    def _peak_rss_mb() -> float:
        return 0.0


def run_sweep(
    media_path: Path | None = None,
    quick: bool = True,
    workers: int | None = None,
    out_file: Path | None = None,
) -> list[dict]:
    """Run parameter sweep benchmark and return results list."""
    with tempfile.TemporaryDirectory() as td:
        tmp_dir = Path(td)
        ws_dir = tmp_dir / "bench_ws"
        ws = Workspace(ws_dir)
        ws.keygen("bench-root", alg="ML-DSA-87")

        duration_s = 4.0 if quick else 10.0
        if media_path is None or not Path(media_path).is_file():
            test_media = make_media("ts", tmp_dir, duration_s=duration_s, fps=10, gop=10)
        else:
            test_media = Path(media_path)

        orig_size = test_media.stat().st_size

        if quick:
            configs = [
                ("court-grade (ML-DSA-44, RS 10+2, block=1)", {
                    "sign": {"alg": "ML-DSA-44", "block_segments": 1},
                    "ec": {"k": 10, "m": 2},
                    "anchors": {"backend": "off"},
                }),
                ("low-storage (ML-DSA-44, RS 20+2, block=5)", {
                    "sign": {"alg": "ML-DSA-44", "block_segments": 5},
                    "ec": {"k": 20, "m": 2},
                    "anchors": {"backend": "off"},
                }),
                ("max-security (ML-DSA-87, RS 10+4, block=1)", {
                    "sign": {"alg": "ML-DSA-87", "block_segments": 1},
                    "ec": {"k": 10, "m": 4},
                    "anchors": {"backend": "off"},
                }),
                ("hybrid (Ed25519+ML-DSA-44, RS 10+2)", {
                    "sign": {"alg": "Ed25519+ML-DSA-44", "block_segments": 1},
                    "ec": {"k": 10, "m": 2},
                    "anchors": {"backend": "off"},
                }),
            ]
        else:
            configs = [
                (f"{alg} blk={blk} ec={k}+{m}", {
                    "sign": {"alg": alg, "block_segments": blk},
                    "ec": {"k": k, "m": m},
                    "anchors": {"backend": "off"},
                })
                for alg in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "Ed25519+ML-DSA-44"]
                for blk in [1, 5]
                for (k, m) in [(10, 2), (20, 2)]
            ]

        results = []
        for label, overrides in configs:
            p_dict = prof._merge(prof.DEFAULTS, overrides)
            if workers:
                p_dict["parallel"]["workers"] = workers
            p = prof.resolve(p_dict)

            bundle_out = tmp_dir / f"bundle_{len(results)}"
            if bundle_out.exists():
                shutil.rmtree(bundle_out)

            tracemalloc.start()
            t0 = time.perf_counter()
            c0 = time.process_time()

            seal_path(test_media, p, ws.root("bench-root"), bundle_out, tsa=ws.tsa(), anchor_log=None)

            c1 = time.process_time()
            t1 = time.perf_counter()
            _, peak_traced = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            wall_s = max(t1 - t0, 1e-6)
            cpu_s = c1 - c0
            bundle_size = sum(f.stat().st_size for f in bundle_out.rglob("*") if f.is_file())
            overhead_pct = ((bundle_size - orig_size) / orig_size) * 100.0
            mb_s = (orig_size / (1024 * 1024)) / wall_s
            rt_factor = duration_s / wall_s

            rep = verify(bundle_out, ws.trust())

            rec = {
                "label": label,
                "alg": p["sign"]["alg"],
                "block_segments": p["sign"]["block_segments"],
                "ec": f"{p['ec']['k']}+{p['ec']['m']}",
                "media_size_bytes": orig_size,
                "bundle_size_bytes": bundle_size,
                "overhead_pct": round(overhead_pct, 2),
                "wall_time_s": round(wall_s, 3),
                "cpu_time_s": round(cpu_s, 3),
                "throughput_mb_s": round(mb_s, 2),
                "realtime_x": round(rt_factor, 2),
                "peak_ram_mb": round(max(peak_traced / (1024 * 1024), _peak_rss_mb()), 2),
                "verified": rep.overall == "VERIFIED",
            }
            results.append(rec)

        if out_file:
            Path(out_file).write_text(json.dumps(results, indent=2))

        return results
