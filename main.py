from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path

from agent.anthropic_provider import AnthropicProvider
from agent.models import AnalysisWindow
from agent.runner import AgentRunError, DetectionAgentRunner
from agent.storage import save_outcome
from agent.tooling import RegistryToolCatalog


def main() -> int:
    _configure_console_encoding()
    _load_env_file(Path(__file__).resolve().parent / ".env")
    parser = _build_parser()
    args = parser.parse_args()
    try:
        window = _resolve_window(args)
        tools = RegistryToolCatalog()
        provider = AnthropicProvider(
            api_key=os.getenv("ANTHROPIC_API_KEY"),
            model=args.model,
            max_tokens=args.max_tokens,
        )
        runner = DetectionAgentRunner(
            provider=provider,
            tools=tools,
            max_steps=args.max_steps,
            max_submission_retries=args.max_submission_retries,
        )
        outcome = runner.run(window)
        destination = save_outcome(outcome, args.output_dir)
    except (ValueError, RuntimeError, ImportError, AgentRunError) as exc:
        print(f"실행 실패: {exc}", file=sys.stderr)
        return 1

    summary = {
        "run_id": outcome.detection.run_id,
        "status": outcome.detection.status,
        "observed_ip_count": outcome.detection.observed_ip_count,
        "investigation_request_count": len(outcome.investigations),
        "usage": outcome.usage.to_dict(),
        "output_file": str(destination.resolve()),
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    if outcome.detection.status == "partial":
        # 판정을 못 받았어도 기록은 저장됐다. cron·모니터링이 구분할 수 있게 1을 돌려준다.
        print(f"미완료: {outcome.detection.summary}", file=sys.stderr)
        return 1
    return 0


def _load_env_file(path: Path) -> None:
    """`.env`를 읽어 환경 변수로 올린다. 이미 설정된 값은 덮지 않는다.

    cron은 로그인 셸을 거치지 않아 `~/.bashrc`의 export를 보지 못한다.
    파일에서 읽는 이 경로가 cron 환경에서 API 키를 전달하는 확실한 방법이다.
    """
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip("\"'")
        if value and key not in os.environ:
            os.environ[key] = value


def _configure_console_encoding() -> None:  # 한글 깨짐 방지
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="replace")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Agentic SOC 감지 에이전트 실행")
    parser.add_argument("--start", help="분석 시작 ISO 8601 시간")
    parser.add_argument("--end", help="분석 종료 ISO 8601 시간")
    parser.add_argument("--minutes", type=int, default=10, help="기본 분석 구간(분)")
    parser.add_argument("--model", default="claude-sonnet-5", help="Anthropic 모델 ID")
    parser.add_argument("--max-steps", type=int, default=12, help="최대 LLM 반복 단계")
    parser.add_argument(
        "--max-submission-retries", type=int, default=3, help="최종 제출 검증 실패 시 재시도 한도"
    )
    parser.add_argument(
        "--max-tokens", type=int, default=16384,
        help="호출당 최대 출력 토큰. 관측 IP 가 많으면 제출이 잘릴 수 있어 넉넉히 잡는다",
    )
    parser.add_argument("--output-dir", default="output", help="결과 JSON 저장 폴더")
    return parser


def _resolve_window(args: argparse.Namespace) -> AnalysisWindow:    # 분석 시간 구간 결정
    if bool(args.start) != bool(args.end):
        raise ValueError("--start와 --end는 함께 지정해야 합니다.")
    if args.start and args.end:
        return AnalysisWindow(start=_parse_datetime(args.start), end=_parse_datetime(args.end))
    if args.minutes <= 0:
        raise ValueError("--minutes는 1 이상이어야 합니다.")
    end = datetime.now().astimezone()
    return AnalysisWindow(start=end - timedelta(minutes=args.minutes), end=end)


def _parse_datetime(value: str) -> datetime:        # 실행 시 인자로 시간을 지정해줬을 때만 호출되는 함수
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError(f"시간대가 없는 시간입니다: {value}")
    return parsed


if __name__ == "__main__":
    raise SystemExit(main())
