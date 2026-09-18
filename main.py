"""조사 에이전트 실행 예시.

실제로 돌려보려면:
1. `pip install -r requirements.txt`
2. Gemini(기본값, 무료 티어 가능): Google AI Studio(aistudio.google.com)에서 API 키 발급 후
   `export GEMINI_API_KEY=...`
   Claude로 돌리고 싶으면 `export LLM_PROVIDER=anthropic` + `export ANTHROPIC_API_KEY=...`
3. build_default_registry(handlers={...})에 팀원들이 구현한 실제 fetch_* 함수를 연결
   (미연결 상태면 mock_tools.py의 목업 데이터로 동작)
4. .env에 AWS 자격 증명 + HOST(S3 파티션의 host= 값)를 채워야 raw log ingestion이 동작함

Triage/감지 에이전트가 파이프라인에서 빠졌기 때문에, seed를 직접 만들어 넣던 예전 방식
대신 raw log부터 시작하는 전체 파이프라인(agent.pipeline.run_investigation_pipeline)을 쓴다.

*** 2026-09-18 추가: 조사 결과 JSON 파일 저장 ***
지금까지는 investigation_result가 콘솔에 출력만 되고 사라졌다. results/ 디렉터리에
investigation_id + 저장 시각을 파일명으로 삼아 JSON 그대로 저장하도록 추가했다.
텍스트 리포트는 따로 저장하지 않는다 — agent/report.py의 format_text_report()가
이 JSON을 입력받아 언제든 재생성할 수 있으므로, JSON을 "원본"으로 보관해두면
텍스트 리포트는 필요할 때마다 다시 뽑아 쓰면 된다.
"""

import json
import os
from datetime import datetime, timezone

from dotenv import load_dotenv

from agent import ClaudeClient, GeminiClient, build_default_registry, run_investigation_pipeline
from agent.report import format_text_report

load_dotenv()  # .env 파일에서 GEMINI_API_KEY / ANTHROPIC_API_KEY / HOST 등을 읽어온다

RESULTS_DIR = "results"


def build_llm_client():
    """LLM_PROVIDER 환경변수로 Gemini/Claude를 선택한다. 기본값은 gemini."""
    provider = os.environ.get("LLM_PROVIDER", "gemini").lower()
    if provider == "anthropic":
        return ClaudeClient()  # ANTHROPIC_API_KEY 환경변수 필요
    if provider == "gemini":
        return GeminiClient()  # GEMINI_API_KEY 환경변수 필요 (무료 티어 가능)
    raise ValueError(f"알 수 없는 LLM_PROVIDER입니다: {provider} (gemini 또는 anthropic만 지원)")


def save_investigation_result(result: dict, output_dir: str = RESULTS_DIR) -> str:
    """조사 결과(investigation_result JSON)를 파일로 저장하고 저장된 경로를 반환한다.

    파일명은 {investigation_id}_{저장시각 UTC}.json 형태다. investigation_id만으로는
    같은 incident가 재조사될 경우 파일명이 겹칠 수 있어(build_investigation_result()가
    날짜 기준 "-001" 고정 접미사를 붙이는 방식이라 하루에 여러 번 조사되면 동일해짐),
    저장 시각(초 단위)을 추가로 붙여 항상 고유하게 만든다.
    """
    os.makedirs(output_dir, exist_ok=True)

    investigation_id = result.get("investigation_id") or result.get("incident_id", "UNKNOWN")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = f"{investigation_id}_{timestamp}.json"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    return filepath


def main() -> None:
    # S3 파티션의 host= 값과 반드시 일치해야 함 (예: "library-web-01"이 아니라 "web-01")
    host = os.environ.get("HOST", "web-01")
    minutes = int(os.environ.get("RAW_LOG_WINDOW_MINUTES", "10"))

    # resolve_ip_geo는 실제 구현은 있지만 지금 우선순위가 아니라서 제외해둔다.
    # get_process_tree는 2026-09-14에 실제 구현 완성돼서 제외 목록에서 뺐다.

    # [2] agent/tools/registry.py가 agent/tools/real/ 폴더를 훑어서
    #     파일명 == 함수명인 것들을 자동으로 찾아 연결함
    tool_registry = build_default_registry(exclude=["resolve_ip_geo"])
    # [3] GeminiClient 생성
    llm_client = build_llm_client()

    # [4] 조사 pipline 실행 agent/pipelin.py 의 run_investigation_pipeline() 실행
    # [44] agent/pipeline.py로부터 조사 결과를 result에 반환
    results = run_investigation_pipeline(
        host=host,
        llm_client=llm_client,
        tool_registry=tool_registry,
        minutes=minutes,
        max_calls=8,
        confidence_threshold=0.85,
    )

    if not results:
        print(f"최근 {minutes}분 동안 {host}에서 조사할 만한 seed 후보가 없었습니다.")
        return

    # [45] 조사 결과 프롬포트에 출력 + JSON 파일로 저장
    for i, result in enumerate(results, start=1):
        print(f"\n{'='*10} 조사 {i}/{len(results)} — {result['incident_id']} {'='*10}")
        print(format_text_report(result))

        saved_path = save_investigation_result(result)
        print(f"[저장 완료] {saved_path}")

    print("\n--- 원본 JSON (raw investigation_result 리스트) ---")
    print(json.dumps(results, ensure_ascii=False, indent=2))


# [1] main() 함수 실행
if __name__ == "__main__":
    main()