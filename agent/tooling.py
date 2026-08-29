from __future__ import annotations

import copy
import importlib
import json
import pkgutil
from typing import Any, Callable, Mapping, Protocol, Sequence


ToolFunction = Callable[..., dict[str, Any]]


class ToolCatalog(Protocol):
    def get_schemas(self) -> list[dict[str, Any]]:
        ...

    def execute(self, name: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        ...


class RegistryToolCatalog:
    def __init__(
        self,
        *,
        package_module: str = "tools",
        registry_module: str = "tools.registry",
    ) -> None:
        try:
            package = importlib.import_module(package_module)
            self._registry = importlib.import_module(registry_module)
        except ModuleNotFoundError as exc:
            raise RuntimeError(
                "도구 팀의 tools 패키지를 찾을 수 없습니다. "
                "프로젝트 루트에서 실행하는지, tools/ 폴더가 있는지 확인하세요."
            ) from exc

        self.import_errors: dict[str, str] = {}
        self._import_tool_modules(package, package_module)

        if not self._registry.get_schemas():
            detail = (
                " 개별 모듈 import 실패: " + json.dumps(self.import_errors, ensure_ascii=False)
                if self.import_errors else ""
            )
            raise RuntimeError(
                "도구 registry가 비어 있습니다. 등록된 도구가 하나도 없으면 "
                "에이전트는 조회 없이 '관측된 접근 없음'으로 끝나 실제 위협을 놓칩니다."
                + detail
            )

    def _import_tool_modules(self, package: Any, package_module: str) -> None:
        """tools 패키지의 하위 모듈을 import 해 @register 를 실행시킨다."""
        for info in pkgutil.iter_modules(package.__path__):
            if info.name.startswith("_"):
                continue
            name = f"{package_module}.{info.name}"
            try:
                importlib.import_module(name)
            except Exception as exc:  # 한 도구의 실패가 전체를 막지 않게 한다.
                self.import_errors[name] = f"{type(exc).__name__}: {exc}"

    def get_schemas(self) -> list[dict[str, Any]]:
        schemas = self._registry.get_schemas()
        return _validate_schema_list(schemas)

    def execute(self, name: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        schemas = {schema["name"]: schema for schema in self.get_schemas()}
        if name not in schemas:
            return _failure(f"등록되지 않은 도구: {name}")
        validation_error = validate_tool_arguments(schemas[name]["input_schema"], arguments)
        if validation_error:
            return _failure(validation_error)

        function = self._registry.get_tool(name)
        if function is None:
            return _failure(f"도구 함수를 찾을 수 없음: {name}")
        try:
            return normalize_tool_result(function(**dict(arguments)))
        except Exception as exc:  # 도구 예외가 에이전트 프로세스를 죽이지 않게 한다.
            return _failure(f"도구 실행 중 예외 발생: {type(exc).__name__}: {exc}")


def normalize_tool_result(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return _failure("도구가 객체가 아닌 결과를 반환함")
    expected = {"success", "data", "error"}
    if set(value.keys()) != expected:
        return _failure("도구 반환 형식은 success/data/error여야 함")
    if not isinstance(value["success"], bool):
        return _failure("도구 결과의 success는 boolean이어야 함")
    if value["success"] and value["error"] is not None:
        return _failure("성공 결과의 error는 null이어야 함")
    if not value["success"] and not isinstance(value["error"], str):
        return _failure("실패 결과의 error는 문자열이어야 함")
    try:
        serialized = json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError):
        return _failure("도구 결과는 JSON으로 직렬화할 수 있어야 함")
    if len(serialized) > 200_000:
        return _failure("도구 결과가 200,000자를 초과함. 집계하거나 잘라서 반환해야 함")
    return dict(value)


def validate_tool_arguments(schema: Mapping[str, Any], arguments: Mapping[str, Any]) -> str | None:
    if not isinstance(arguments, Mapping):
        return "도구 인자는 객체여야 함"
    properties = schema.get("properties", {})
    required = set(schema.get("required", []))
    missing = required - set(arguments.keys())
    if missing:
        return f"필수 도구 인자 누락: {sorted(missing)}"
    if schema.get("additionalProperties") is False:
        extra = set(arguments.keys()) - set(properties.keys())
        if extra:
            return f"알 수 없는 도구 인자: {sorted(extra)}"
    for key, value in arguments.items():
        definition = properties.get(key)
        if not isinstance(definition, Mapping):
            continue
        expected_type = definition.get("type")
        if expected_type and not _matches_json_type(value, expected_type):
            return f"도구 인자 {key}의 타입이 올바르지 않음: {expected_type} 필요"
        if "enum" in definition and value not in definition["enum"]:
            return f"도구 인자 {key}가 허용된 값이 아님"
    return None


def _matches_json_type(value: Any, expected: str | Sequence[str]) -> bool:
    expected_types = [expected] if isinstance(expected, str) else list(expected)
    checks = {
        "null": value is None,
        "boolean": isinstance(value, bool),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "string": isinstance(value, str),
        "array": isinstance(value, list),
        "object": isinstance(value, Mapping),
    }
    return any(checks.get(item, False) for item in expected_types)


def _validate_schema_list(schemas: Any) -> list[dict[str, Any]]:
    if not isinstance(schemas, list):
        raise ValueError("get_schemas()는 리스트를 반환해야 합니다.")
    validated: list[dict[str, Any]] = []
    names: set[str] = set()
    for schema in schemas:
        if not isinstance(schema, Mapping):
            raise ValueError("도구 스키마는 객체여야 합니다.")
        if set(schema.keys()) != {"name", "description", "input_schema"}:
            raise ValueError("도구 스키마는 name/description/input_schema만 포함해야 합니다.")
        name = schema["name"]
        if not isinstance(name, str) or not name:
            raise ValueError("도구 이름은 비어 있지 않은 문자열이어야 합니다.")
        if name in names:
            raise ValueError(f"중복 도구 이름: {name}")
        if not isinstance(schema["description"], str) or not schema["description"].strip():
            raise ValueError(f"도구 설명 누락: {name}")
        input_schema = schema["input_schema"]
        if not isinstance(input_schema, Mapping) or input_schema.get("type") != "object":
            raise ValueError(f"도구 input_schema는 object여야 합니다: {name}")
        names.add(name)
        validated.append(copy.deepcopy(dict(schema)))
    return validated


def _failure(reason: str) -> dict[str, Any]:
    return {"success": False, "data": None, "error": reason}
