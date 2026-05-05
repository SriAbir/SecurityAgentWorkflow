#!/usr/bin/env python
import json
import warnings
from pathlib import Path

from crew import SecurityCaseStudy
from planners.static_planner import StaticPlannerRouter

warnings.filterwarnings("ignore", category=SyntaxWarning, module="pysbd")


def load_case(case_id: str = "case_15") -> dict:
    """
    Load metadata and source code for a vulnerability case.
    """
    project_root = Path(__file__).resolve().parents[2]
    case_dir = project_root / "cases" / case_id

    metadata_path = case_dir / "metadata.json"
    if not metadata_path.exists():
        raise FileNotFoundError(f"metadata.json not found at: {metadata_path}")

    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))

    if "filename" not in metadata:
        raise KeyError("metadata.json must contain a 'filename' field")

    code_path = case_dir / metadata["filename"]
    if not code_path.exists():
        raise FileNotFoundError(f"Code file not found at: {code_path}")

    code = code_path.read_text(encoding="utf-8", errors="ignore")

    return {
        "project_root": str(project_root),
        "case_dir": str(case_dir),
        "code_path": str(code_path),
        "metadata": metadata,
        "code": code,
    }


def run():
    """
    Run the crew on a single vulnerability case.
    """
    case = load_case("case_15")
    metadata = case["metadata"]
    filename = metadata.get("filename", "unknown")

    planner_router = StaticPlannerRouter()
    detected_language = planner_router.detect_language(filename)
    planner_hints = planner_router.analyze(case["code"], filename)

    print(f"Running case: {metadata.get('ID', 'unknown')}")
    print(f"File: {filename}")
    print(f"Language: {metadata.get('language', detected_language)}")
    print("-" * 60)
    print("Static Planner Hints:")
    print(json.dumps(planner_hints, indent=2))
    print("-" * 60)

    inputs = {
        "code": case["code"],
        "case_id": metadata.get("ID", "case_15"),
        "filename": filename,
        "language": metadata.get("language", detected_language),
        "planner_hints": json.dumps(planner_hints, indent=2)
    }

    try:
        result = SecurityCaseStudy().crew().kickoff(inputs=inputs)
        print("\nCrew Output:\n")
        print(result)
        return result
    except Exception as e:
        raise Exception(f"An error occurred while running the crew: {e}")


if __name__ == "__main__":
    run()