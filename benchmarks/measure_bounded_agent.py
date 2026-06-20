#!/usr/bin/env python3
"""Reproducible measurement harness for bounded-resource local LLM agents.

The harness measures serialized specialist routing against an Ollama-compatible
HTTP API. It records model residency, host memory, latency, token throughput,
and route correctness. It has no mandatory third-party dependencies; psutil is
used when available for higher-quality process-memory samples.

This file intentionally separates measured facts from paper claims. A result is
only marked ``valid_single_resident`` when every sample contains at most one
loaded model and the backend confirms the requested model is resident.
"""
from __future__ import annotations

import argparse
import csv
import ctypes
import json
import math
import os
import platform
import re
import statistics
import threading
import time
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Protocol, Sequence

SCHEMA_VERSION = "1.0"
DEFAULT_BASE_URL = "http://127.0.0.1:11434"


@dataclass(frozen=True)
class RouteProfile:
    name: str
    model: str
    temperature: float = 0.2
    top_p: float = 0.9
    repeat_penalty: float = 1.05
    num_ctx: int = 4096


@dataclass(frozen=True)
class WorkItem:
    item_id: str
    route: str
    prompt: str
    expected_route: str | None = None


@dataclass
class MemorySample:
    t_s: float
    host_used_mb: float
    process_rss_mb: float | None
    loaded_models: list[str] = field(default_factory=list)


@dataclass
class ItemResult:
    item_id: str
    requested_route: str
    selected_route: str
    model: str
    route_correct: bool | None
    wall_time_s: float
    total_duration_s: float | None
    prompt_eval_count: int | None
    eval_count: int | None
    eval_duration_s: float | None
    tokens_per_second: float | None
    response_sha256: str
    resident_model_sets: list[list[str]]
    max_simultaneous_models: int
    peak_host_used_mb: float
    peak_process_rss_mb: float | None
    valid_single_resident: bool
    error: str | None = None


class Backend(Protocol):
    def list_models(self) -> list[str]: ...
    def loaded_models(self) -> list[str]: ...
    def unload(self, model: str) -> None: ...
    def generate(self, model: str, prompt: str, options: Mapping[str, Any]) -> Mapping[str, Any]: ...


def _json_request(url: str, payload: Mapping[str, Any] | None = None, timeout: float = 120.0) -> Any:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=data)
    request.add_header("Accept", "application/json")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


class OllamaBackend:
    def __init__(self, base_url: str = DEFAULT_BASE_URL, timeout: float = 300.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def list_models(self) -> list[str]:
        data = _json_request(f"{self.base_url}/api/tags", timeout=self.timeout)
        return [model.get("name", "") for model in data.get("models", []) if model.get("name")]

    def loaded_models(self) -> list[str]:
        data = _json_request(f"{self.base_url}/api/ps", timeout=self.timeout)
        return [model.get("name", "") for model in data.get("models", []) if model.get("name")]

    def unload(self, model: str) -> None:
        _json_request(
            f"{self.base_url}/api/generate",
            {"model": model, "prompt": "", "stream": False, "keep_alive": 0},
            timeout=self.timeout,
        )

    def generate(self, model: str, prompt: str, options: Mapping[str, Any]) -> Mapping[str, Any]:
        return _json_request(
            f"{self.base_url}/api/generate",
            {
                "model": model,
                "prompt": prompt,
                "stream": False,
                "keep_alive": -1,
                "options": dict(options),
            },
            timeout=self.timeout,
        )


def route_prompt(prompt: str) -> str:
    """Deterministic baseline router used for reproducible ablations."""
    text = prompt.lower()
    code_markers = (
        "```", "traceback", "exception", "function", "class ", "def ",
        "python", "javascript", "typescript", "rust", "compile", "debug",
        "refactor", "unit test", "sql", "regex",
    )
    math_markers = (
        "calculate", "solve", "equation", "probability", "integral",
        "derivative", "theorem", "proof", "matrix", "algebra", "geometry",
        "percent", "ratio",
    )
    chat_markers = (
        "explain", "compare", "why", "brainstorm", "write", "summarize",
        "advice", "plan", "story", "essay", "discuss",
    )
    if any(marker in text for marker in code_markers):
        return "code"
    if any(marker in text for marker in math_markers) or re.search(r"\b\d+\s*[+*/^-]\s*\d+\b", text):
        return "math"
    if any(marker in text for marker in chat_markers) or len(text.split()) > 32:
        return "chat"
    return "fast"


def theoretical_peak_ram_mb(
    base_mb: float,
    guardrail_mb: float,
    router_mb: float,
    model_footprints_mb: Sequence[float],
    transient_mb: float = 0.0,
) -> float:
    """Peak-RAM upper bound under strict single-model residency."""
    if min(base_mb, guardrail_mb, router_mb, transient_mb) < 0:
        raise ValueError("memory terms must be non-negative")
    if not model_footprints_mb:
        raise ValueError("at least one model footprint is required")
    if any(value < 0 for value in model_footprints_mb):
        raise ValueError("model footprints must be non-negative")
    return base_mb + guardrail_mb + router_mb + max(model_footprints_mb) + transient_mb


def _host_memory_used_mb() -> float:
    try:
        import psutil  # type: ignore
        return float(psutil.virtual_memory().used) / (1024 * 1024)
    except Exception:
        pass

    if platform.system() == "Windows":
        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]
        status = MEMORYSTATUSEX()
        status.dwLength = ctypes.sizeof(status)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return float(status.ullTotalPhys - status.ullAvailPhys) / (1024 * 1024)

    meminfo = Path("/proc/meminfo")
    if meminfo.exists():
        values: dict[str, float] = {}
        for line in meminfo.read_text(encoding="utf-8").splitlines():
            key, raw = line.split(":", 1)
            values[key] = float(raw.strip().split()[0]) / 1024.0
        return values.get("MemTotal", 0.0) - values.get("MemAvailable", 0.0)
    return 0.0


def _process_rss_mb() -> float | None:
    try:
        import psutil  # type: ignore
        return float(psutil.Process(os.getpid()).memory_info().rss) / (1024 * 1024)
    except Exception:
        return None


def _sha256_text(text: str) -> str:
    import hashlib
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


class MemorySampler:
    def __init__(self, backend: Backend, interval_s: float = 0.2) -> None:
        self.backend = backend
        self.interval_s = max(interval_s, 0.02)
        self.samples: list[MemorySample] = []
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._start = 0.0

    def start(self) -> None:
        self._start = time.perf_counter()
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                loaded = sorted(self.backend.loaded_models())
            except Exception:
                loaded = []
            self.samples.append(
                MemorySample(
                    t_s=time.perf_counter() - self._start,
                    host_used_mb=_host_memory_used_mb(),
                    process_rss_mb=_process_rss_mb(),
                    loaded_models=loaded,
                )
            )
            self._stop.wait(self.interval_s)

    def stop(self) -> list[MemorySample]:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=max(1.0, self.interval_s * 4))
        try:
            loaded = sorted(self.backend.loaded_models())
        except Exception:
            loaded = []
        self.samples.append(
            MemorySample(
                t_s=time.perf_counter() - self._start,
                host_used_mb=_host_memory_used_mb(),
                process_rss_mb=_process_rss_mb(),
                loaded_models=loaded,
            )
        )
        return list(self.samples)


def ensure_only_model(backend: Backend, selected_model: str, all_models: Iterable[str]) -> None:
    """Unload conflicting resident models and wait for the unload barrier."""
    known = set(all_models)
    if selected_model not in known:
        raise RuntimeError(f"selected model is not installed: {selected_model}")
    for model in sorted(set(backend.loaded_models())):
        if model != selected_model:
            backend.unload(model)
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        loaded = backend.loaded_models()
        if all(model == selected_model for model in loaded):
            return
        time.sleep(0.1)
    raise RuntimeError(f"unload barrier failed; still resident: {backend.loaded_models()}")


def run_item(
    backend: Backend,
    profiles: Mapping[str, RouteProfile],
    item: WorkItem,
    all_models: Sequence[str],
    sample_interval_s: float = 0.2,
) -> tuple[ItemResult, list[MemorySample]]:
    selected_route = route_prompt(item.prompt) if item.route == "auto" else item.route
    if selected_route not in profiles:
        raise KeyError(f"route {selected_route!r} has no profile")
    profile = profiles[selected_route]
    ensure_only_model(backend, profile.model, all_models)

    sampler = MemorySampler(backend, interval_s=sample_interval_s)
    sampler.start()
    started = time.perf_counter()
    error: str | None = None
    payload: Mapping[str, Any] = {}
    try:
        payload = backend.generate(
            profile.model,
            item.prompt,
            {
                "temperature": profile.temperature,
                "top_p": profile.top_p,
                "repeat_penalty": profile.repeat_penalty,
                "num_ctx": profile.num_ctx,
            },
        )
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
    wall = time.perf_counter() - started
    samples = sampler.stop()

    response = str(payload.get("response", ""))
    eval_count = _optional_int(payload.get("eval_count"))
    eval_duration_ns = _optional_float(payload.get("eval_duration"))
    eval_duration_s = None if eval_duration_ns is None else eval_duration_ns / 1_000_000_000.0
    tokens_per_second = (
        eval_count / eval_duration_s
        if eval_count is not None and eval_duration_s and eval_duration_s > 0
        else None
    )
    total_duration_ns = _optional_float(payload.get("total_duration"))
    resident_sets = [sample.loaded_models for sample in samples]
    max_models = max((len(models) for models in resident_sets), default=0)
    requested_seen = any(profile.model in models for models in resident_sets)
    valid_single = error is None and max_models <= 1 and requested_seen

    peak_host = max((sample.host_used_mb for sample in samples), default=_host_memory_used_mb())
    rss_values = [sample.process_rss_mb for sample in samples if sample.process_rss_mb is not None]
    peak_rss = max(rss_values) if rss_values else None
    route_correct = None if item.expected_route is None else selected_route == item.expected_route

    result = ItemResult(
        item_id=item.item_id,
        requested_route=item.route,
        selected_route=selected_route,
        model=profile.model,
        route_correct=route_correct,
        wall_time_s=wall,
        total_duration_s=None if total_duration_ns is None else total_duration_ns / 1_000_000_000.0,
        prompt_eval_count=_optional_int(payload.get("prompt_eval_count")),
        eval_count=eval_count,
        eval_duration_s=eval_duration_s,
        tokens_per_second=tokens_per_second,
        response_sha256=_sha256_text(response),
        resident_model_sets=resident_sets,
        max_simultaneous_models=max_models,
        peak_host_used_mb=peak_host,
        peak_process_rss_mb=peak_rss,
        valid_single_resident=valid_single,
        error=error,
    )
    return result, samples


def _optional_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _optional_float(value: Any) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def validate_results(results: Sequence[ItemResult], strict_routes: bool = False) -> list[str]:
    errors: list[str] = []
    for result in results:
        if result.error:
            errors.append(f"{result.item_id}: generation error: {result.error}")
        if not result.valid_single_resident:
            errors.append(
                f"{result.item_id}: residency invariant failed "
                f"(max={result.max_simultaneous_models}, model={result.model})"
            )
        if strict_routes and result.route_correct is False:
            errors.append(
                f"{result.item_id}: expected route differs from selected route {result.selected_route}"
            )
    return errors


def summarize(results: Sequence[ItemResult]) -> dict[str, Any]:
    tps = [result.tokens_per_second for result in results if result.tokens_per_second is not None]
    walls = [result.wall_time_s for result in results if result.error is None]
    return {
        "items": len(results),
        "successful_items": sum(result.error is None for result in results),
        "single_resident_items": sum(result.valid_single_resident for result in results),
        "route_accuracy": _route_accuracy(results),
        "median_tokens_per_second": statistics.median(tps) if tps else None,
        "median_wall_time_s": statistics.median(walls) if walls else None,
        "peak_host_used_mb": max((result.peak_host_used_mb for result in results), default=None),
        "max_simultaneous_models": max((result.max_simultaneous_models for result in results), default=0),
    }


def _route_accuracy(results: Sequence[ItemResult]) -> float | None:
    labeled = [result for result in results if result.route_correct is not None]
    if not labeled:
        return None
    return sum(bool(result.route_correct) for result in labeled) / len(labeled)


def write_json(path: Path, config: Mapping[str, Any], results: Sequence[ItemResult]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    document = {
        "schema_version": SCHEMA_VERSION,
        "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "config": config,
        "summary": summarize(results),
        "results": [asdict(result) for result in results],
    }
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_csv(path: Path, samples_by_item: Mapping[str, Sequence[MemorySample]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["item_id", "t_s", "host_used_mb", "process_rss_mb", "loaded_models"])
        for item_id, samples in samples_by_item.items():
            for sample in samples:
                writer.writerow([
                    item_id,
                    f"{sample.t_s:.6f}",
                    f"{sample.host_used_mb:.3f}",
                    "" if sample.process_rss_mb is None else f"{sample.process_rss_mb:.3f}",
                    "|".join(sample.loaded_models),
                ])


def write_svg(path: Path, samples_by_item: Mapping[str, Sequence[MemorySample]]) -> None:
    """Write a dependency-free RAM-over-time SVG with one polyline per item."""
    width, height = 1000, 540
    left, right, top, bottom = 80, 30, 40, 70
    all_points = [sample for samples in samples_by_item.values() for sample in samples]
    max_t = max((sample.t_s for sample in all_points), default=1.0) or 1.0
    min_mem = min((sample.host_used_mb for sample in all_points), default=0.0)
    max_mem = max((sample.host_used_mb for sample in all_points), default=min_mem + 1.0)
    if math.isclose(min_mem, max_mem):
        max_mem = min_mem + 1.0

    def xy(sample: MemorySample) -> tuple[float, float]:
        x = left + sample.t_s / max_t * (width - left - right)
        y = top + (max_mem - sample.host_used_mb) / (max_mem - min_mem) * (height - top - bottom)
        return x, y

    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="white"/>',
        f'<line x1="{left}" y1="{top}" x2="{left}" y2="{height-bottom}" stroke="black"/>',
        f'<line x1="{left}" y1="{height-bottom}" x2="{width-right}" y2="{height-bottom}" stroke="black"/>',
        f'<text x="{width/2}" y="{height-20}" text-anchor="middle" font-family="sans-serif">Time (s)</text>',
        f'<text x="20" y="{height/2}" transform="rotate(-90 20 {height/2})" text-anchor="middle" font-family="sans-serif">Host memory used (MB)</text>',
        f'<text x="{width/2}" y="24" text-anchor="middle" font-family="sans-serif" font-weight="bold">Serialized specialist routing: RAM over time</text>',
        f'<text x="{left-10}" y="{top+5}" text-anchor="end" font-family="sans-serif" font-size="12">{max_mem:.0f}</text>',
        f'<text x="{left-10}" y="{height-bottom+5}" text-anchor="end" font-family="sans-serif" font-size="12">{min_mem:.0f}</text>',
        f'<text x="{left}" y="{height-bottom+20}" text-anchor="middle" font-family="sans-serif" font-size="12">0</text>',
        f'<text x="{width-right}" y="{height-bottom+20}" text-anchor="middle" font-family="sans-serif" font-size="12">{max_t:.1f}</text>',
    ]
    palette = ["black", "dimgray", "slategray", "gray"]
    for index, (item_id, samples) in enumerate(samples_by_item.items()):
        points = " ".join(f"{x:.2f},{y:.2f}" for x, y in map(xy, samples))
        color = palette[index % len(palette)]
        lines.append(f'<polyline points="{points}" fill="none" stroke="{color}" stroke-width="2"/>')
        lines.append(
            f'<text x="{left + 10}" y="{top + 18 + index*18}" font-family="sans-serif" font-size="12" fill="{color}">{_xml_escape(item_id)}</text>'
        )
    lines.append("</svg>")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _xml_escape(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def load_config(path: Path) -> tuple[dict[str, RouteProfile], list[WorkItem], dict[str, Any]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    profiles = {
        name: RouteProfile(name=name, **settings)
        for name, settings in raw["profiles"].items()
    }
    items = [WorkItem(**item) for item in raw["work_items"]]
    return profiles, items, raw


class FakeBackend:
    """Deterministic backend used only by self-tests and CI."""
    def __init__(self) -> None:
        self._loaded: list[str] = []
        self._models = ["fast:0.5b", "chat:1.5b", "code:3b", "math:1.5b"]

    def list_models(self) -> list[str]:
        return list(self._models)

    def loaded_models(self) -> list[str]:
        return list(self._loaded)

    def unload(self, model: str) -> None:
        self._loaded = [name for name in self._loaded if name != model]

    def generate(self, model: str, prompt: str, options: Mapping[str, Any]) -> Mapping[str, Any]:
        self._loaded = [model]
        time.sleep(0.06)
        return {
            "response": f"fake response for {prompt}",
            "prompt_eval_count": len(prompt.split()),
            "eval_count": 12,
            "eval_duration": 600_000_000,
            "total_duration": 700_000_000,
        }


def self_test() -> dict[str, Any]:
    profiles = {
        "fast": RouteProfile("fast", "fast:0.5b"),
        "chat": RouteProfile("chat", "chat:1.5b"),
        "code": RouteProfile("code", "code:3b", temperature=0.0),
        "math": RouteProfile("math", "math:1.5b", temperature=0.0),
    }
    items = [
        WorkItem("route-fast", "auto", "Translate hello to Spanish", "fast"),
        WorkItem("route-chat", "auto", "Explain why local AI can improve privacy", "chat"),
        WorkItem("route-code", "auto", "Debug this Python function", "code"),
        WorkItem("route-math", "auto", "Calculate 17 * 23", "math"),
    ]
    backend = FakeBackend()
    results: list[ItemResult] = []
    samples_by_item: dict[str, list[MemorySample]] = {}
    for item in items:
        result, samples = run_item(
            backend, profiles, item, backend.list_models(), sample_interval_s=0.02
        )
        results.append(result)
        samples_by_item[item.item_id] = samples
    errors = validate_results(results, strict_routes=True)
    if errors:
        raise AssertionError("; ".join(errors))
    if not math.isclose(theoretical_peak_ram_mb(100, 5, 5, [500, 900, 700], 10), 1020):
        raise AssertionError("peak-RAM formula self-test failed")
    return {"summary": summarize(results), "results": results, "samples": samples_by_item}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, help="JSON benchmark configuration")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--output-dir", type=Path, default=Path("benchmarks/results/latest"))
    parser.add_argument("--sample-interval", type=float, default=0.2)
    parser.add_argument("--strict-routes", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.self_test:
        report = self_test()
        print(json.dumps(report["summary"], indent=2, sort_keys=True))
        return 0
    if not args.config:
        raise SystemExit("--config is required unless --self-test is used")

    profiles, items, raw_config = load_config(args.config)
    backend = OllamaBackend(args.base_url)
    installed = backend.list_models()
    required = sorted({profile.model for profile in profiles.values()})
    missing = [model for model in required if model not in installed]
    if missing:
        raise SystemExit(f"required Ollama models are missing: {missing}")

    results: list[ItemResult] = []
    samples_by_item: dict[str, list[MemorySample]] = {}
    for item in items:
        print(f"[{item.item_id}] route={item.route}", flush=True)
        result, samples = run_item(
            backend,
            profiles,
            item,
            installed,
            sample_interval_s=args.sample_interval,
        )
        results.append(result)
        samples_by_item[item.item_id] = samples
        print(
            f"  model={result.model} tps={result.tokens_per_second} "
            f"max_resident={result.max_simultaneous_models} valid={result.valid_single_resident}",
            flush=True,
        )

    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_json(args.output_dir / "results.json", raw_config, results)
    write_csv(args.output_dir / "memory_samples.csv", samples_by_item)
    write_svg(args.output_dir / "ram_over_time.svg", samples_by_item)
    errors = validate_results(results, strict_routes=args.strict_routes)
    print(json.dumps(summarize(results), indent=2, sort_keys=True))
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
