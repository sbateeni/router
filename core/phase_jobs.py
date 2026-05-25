"""Parallel tool job engine — run many scanners concurrently with timeouts + artifact tracking."""

from __future__ import annotations

import concurrent.futures
import json
import os
import threading
import time
import traceback
from dataclasses import dataclass, field
from typing import Any, Callable

from core.phase_log import begin_phase, end_phase, set_thread_phase, write_phase
from core.scan_config import get_scan_profile
from core.utils import valid_env_value

_print_lock = threading.Lock()


@dataclass
class JobSpec:
    name: str
    fn: Callable[[], Any]
    timeout: int | None = None
    artifacts: tuple[str, ...] = ()
    phase: str = "1"
    critical: bool = False


@dataclass
class JobResult:
    name: str
    ok: bool
    elapsed: float
    result: Any = None
    error: str = ""
    timed_out: bool = False
    artifacts_found: list[str] = field(default_factory=list)


def _default_workers() -> int:
    profile = get_scan_profile()
    env = os.environ.get("AUTOPWN_MAX_WORKERS", "").strip()
    if valid_env_value(env):
        try:
            return max(1, int(env))
        except ValueError:
            pass
    return int(profile.get("parallel_workers", 6))


def _default_job_timeout() -> int:
    profile = get_scan_profile()
    env = os.environ.get("AUTOPWN_JOB_TIMEOUT", "").strip()
    if valid_env_value(env):
        try:
            return int(env)
        except ValueError:
            pass
    return int(profile.get("job_timeout_default", 600))


def _log(msg: str, phase_id: str) -> None:
    with _print_lock:
        print(msg)
    write_phase(phase_id, msg)


def _check_artifacts(target_dir: str, names: tuple[str, ...]) -> list[str]:
    found: list[str] = []
    for name in names:
        path = os.path.join(target_dir, name) if not os.path.isabs(name) else name
        if os.path.isfile(path) and os.path.getsize(path) > 0:
            found.append(name)
    return found


class PhaseRunner:
    """Submit independent tool jobs; wait with per-job and optional group timeout."""

    def __init__(
        self,
        target_dir: str,
        phase_id: str,
        label: str = "",
        max_workers: int | None = None,
    ):
        self.target_dir = target_dir
        self.phase_id = str(phase_id)
        self.label = label or f"Phase {phase_id}"
        self.max_workers = max_workers or _default_workers()
        self.default_timeout = _default_job_timeout()
        self.jobs: list[JobSpec] = []

    def add(
        self,
        name: str,
        fn: Callable[[], Any],
        *,
        timeout: int | None = None,
        artifacts: tuple[str, ...] | list[str] = (),
        critical: bool = False,
    ) -> None:
        arts = tuple(artifacts) if artifacts else ()
        self.jobs.append(
            JobSpec(
                name=name,
                fn=fn,
                timeout=timeout if timeout is not None else self.default_timeout,
                artifacts=arts,
                phase=self.phase_id,
                critical=critical,
            )
        )

    def _run_one(self, job: JobSpec) -> JobResult:
        set_thread_phase(self.phase_id)
        start = time.monotonic()
        _log(f"[JOB START] {job.name} (timeout={job.timeout}s)", self.phase_id)
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as inner:
                future = inner.submit(job.fn)
                result = future.result(timeout=job.timeout)
            elapsed = time.monotonic() - start
            arts = _check_artifacts(self.target_dir, job.artifacts)
            _log(f"[JOB OK] {job.name} ({elapsed:.1f}s) artifacts={arts or 'none'}", self.phase_id)
            return JobResult(
                name=job.name,
                ok=True,
                elapsed=elapsed,
                result=result,
                artifacts_found=arts,
            )
        except concurrent.futures.TimeoutError:
            elapsed = time.monotonic() - start
            msg = f"timed out after {job.timeout}s"
            _log(f"[JOB TIMEOUT] {job.name} — {msg}", self.phase_id)
            return JobResult(name=job.name, ok=False, elapsed=elapsed, error=msg, timed_out=True)
        except Exception as exc:
            elapsed = time.monotonic() - start
            tb = traceback.format_exc()
            _log(f"[JOB FAIL] {job.name}: {exc}", self.phase_id)
            write_phase(self.phase_id, tb)
            return JobResult(name=job.name, ok=False, elapsed=elapsed, error=str(exc))
        finally:
            set_thread_phase(None)

    def run(self, group_timeout: int | None = None) -> dict[str, JobResult]:
        if not self.jobs:
            return {}

        profile = get_scan_profile()
        if group_timeout is None:
            env_gt = os.environ.get("AUTOPWN_PHASE_TIMEOUT", "").strip()
            if valid_env_value(env_gt):
                try:
                    group_timeout = int(env_gt)
                except ValueError:
                    group_timeout = None
            else:
                group_timeout = profile.get("phase_group_timeout")

        begin_phase(self.phase_id, self.label, self.target_dir)
        _log(
            f"[*] Parallel pool: {len(self.jobs)} job(s), workers={self.max_workers}, "
            f"group_timeout={group_timeout or 'none'}",
            self.phase_id,
        )

        results: dict[str, JobResult] = {}
        deadline = time.time() + group_timeout if group_timeout else None

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            future_map = {pool.submit(self._run_one, job): job for job in self.jobs}
            pending = set(future_map.keys())

            while pending:
                wait_timeout = None
                if deadline:
                    remaining = deadline - time.time()
                    if remaining <= 0:
                        _log(f"[!] Group timeout — cancelling {len(pending)} pending job(s)", self.phase_id)
                        for fut in pending:
                            fut.cancel()
                        break
                    wait_timeout = min(remaining, 30.0)

                done, pending = concurrent.futures.wait(
                    pending,
                    timeout=wait_timeout,
                    return_when=concurrent.futures.FIRST_COMPLETED,
                )
                for fut in done:
                    job = future_map[fut]
                    try:
                        results[job.name] = fut.result()
                    except Exception as exc:
                        results[job.name] = JobResult(
                            name=job.name, ok=False, elapsed=0, error=str(exc),
                        )

        ok_n = sum(1 for r in results.values() if r.ok)
        to_n = sum(1 for r in results.values() if r.timed_out)
        summary = f"Jobs: {ok_n}/{len(self.jobs)} OK, {to_n} timeout(s)"
        _log(f"[+] {summary}", self.phase_id)
        self._save_manifest(results, summary)
        end_phase(self.phase_id, summary)
        return results

    def _save_manifest(self, results: dict[str, JobResult], summary: str) -> None:
        manifest = {
            "phase": self.phase_id,
            "label": self.label,
            "summary": summary,
            "workers": self.max_workers,
            "jobs": {
                name: {
                    "ok": r.ok,
                    "elapsed": round(r.elapsed, 2),
                    "timed_out": r.timed_out,
                    "error": r.error,
                    "artifacts": r.artifacts_found,
                }
                for name, r in results.items()
            },
        }
        path = os.path.join(self.target_dir, f"PHASE_{self.phase_id}_JOBS.json")
        try:
            os.makedirs(self.target_dir, exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(manifest, fh, indent=2, ensure_ascii=False)
        except OSError:
            pass


def run_jobs(
    target_dir: str,
    phase_id: str,
    label: str,
    specs: list[tuple[str, Callable[[], Any], dict]],
    *,
    max_workers: int | None = None,
    group_timeout: int | None = None,
) -> dict[str, JobResult]:
    """Quick helper: specs = [(name, fn, {timeout, artifacts}), ...]."""
    runner = PhaseRunner(target_dir, phase_id, label, max_workers=max_workers)
    for name, fn, opts in specs:
        runner.add(name, fn, **opts)
    return runner.run(group_timeout=group_timeout)
