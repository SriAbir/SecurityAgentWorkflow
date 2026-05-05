from pathlib import Path
from planners.c_planner import CStaticPlanner
from planners.python_planner import PythonStaticPlanner


class StaticPlannerRouter:
    def __init__(self):
        self.c_planner = CStaticPlanner()
        self.python_planner = PythonStaticPlanner()

    def detect_language(self, filename: str) -> str:
        suffix = Path(filename).suffix.lower()
        if suffix in [".c", ".h"]:
            return "C"
        if suffix == ".py":
            return "Python"
        return "Unknown"

    def analyze(self, code: str, filename: str):
        language = self.detect_language(filename)

        if language == "C":
            return self.c_planner.analyze(code, filename=filename)

        if language == "Python":
            return self.python_planner.analyze(code, filename=filename)

        return {
            "language": language,
            "detected_issues": [],
            "analysis_focus": ["Unsupported file type for static planner"]
        }