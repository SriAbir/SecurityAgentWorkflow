import re
import json
from typing import List, Dict


class PythonStaticPlanner:
    def __init__(self):
      
        self.request_source_patterns = [
            r'request\.(args|get_json|form|values|json|data)',
            r'\b(request|req)\[',
            r'\b(input|user_input|url|path|filename|name|query|target)\b'
        ]

        self.ssrf_patterns = [
            r'\brequests\.(get|post|put|delete|request)\s*\(',
            r'\bhttpx\.(get|post|put|delete|request)\s*\(',
            r'\burllib\.request\.urlopen\s*\('
        ]

        self.sqli_patterns = [
            r'SELECT\s+.*FROM',
            r'INSERT\s+INTO',
            r'UPDATE\s+.*SET',
            r'DELETE\s+FROM'
        ]

        self.sqli_exec_patterns = [
            r'\.execute\s*\(',
            r'\.executemany\s*\(',
            r'\bsession\.execute\s*\('
        ]

        self.xss_patterns = [
            r'\brender_template_string\s*\(',
            r'\bMarkup\s*\(',
            r'\bmark_safe\s*\(',
            r'return\s+f["\'].*<.*>.*["\']',
            r'return\s+["\'].*<.*>.*["\']\s*\+'
        ]

        self.path_patterns = [
            r'\bopen\s*\(',
            r'\bsend_file\s*\(',
            r'\bFileResponse\s*\(',
            r'\bos\.path\.join\s*\('
        ]

    def get_region(self, lines: List[str], line_no: int, window: int = 2) -> Dict:
        start = max(1, line_no - window)
        end = min(len(lines), line_no + window)
        snippet = []
        for i in range(start, end + 1):
            snippet.append({
                "line": i,
                "text": lines[i - 1].rstrip()
            })
        return {
            "start_line": start,
            "end_line": end,
            "snippet": snippet
        }

    def analyze(self, code: str, filename: str = "unknown.py") -> Dict:
        lines = code.splitlines()
        findings = []

        findings.extend(self.detect_ssrf(lines, filename))
        findings.extend(self.detect_sqli(lines, filename))
        findings.extend(self.detect_xss(lines, filename))
        findings.extend(self.detect_path_traversal(lines, filename))

        return {
            "language": "Python",
            "detected_issues": findings,
            "analysis_focus": self._build_focus(findings)
        }

    def _has_request_source_nearby(self, lines: List[str], idx: int, window: int = 5) -> bool:
        start = max(0, idx - window)
        end = min(len(lines), idx + 1)
        chunk = "\n".join(lines[start:end])
        return any(re.search(p, chunk) for p in self.request_source_patterns)

    def detect_ssrf(self, lines: List[str], filename: str) -> List[Dict]:
        findings = []
        for i, line in enumerate(lines, start=1):
            if any(re.search(p, line) for p in self.ssrf_patterns):
                confidence = "MEDIUM"
                reason = "Outbound HTTP request detected."
                if self._has_request_source_nearby(lines, i - 1):
                    confidence = "HIGH"
                    reason = "Outbound HTTP request appears influenced by request/user input."
                findings.append({
                    "cwe": "CWE-918",
                    "type": "Potential SSRF",
                    "file": filename,
                    "line": i,
                    "column": 1,
                    "code": line.strip(),
                    "region": self.get_region(lines, i, window=2),
                    "reason": reason,
                    "confidence": confidence
                })
        return findings

    def detect_sqli(self, lines: List[str], filename: str) -> List[Dict]:
        findings = []
        for i, line in enumerate(lines, start=1):
            has_sql_shape = any(re.search(p, line, re.IGNORECASE) for p in self.sqli_patterns)
            has_dynamic_build = (
                "f\"" in line or "f'" in line or ".format(" in line or "%" in line or "+" in line
            )
            if has_sql_shape and has_dynamic_build:
                findings.append({
                    "cwe": "CWE-89",
                    "type": "Potential SQL Injection",
                    "file": filename,
                    "line": i,
                    "column": 1,
                    "code": line.strip(),
                    "region": self.get_region(lines, i, window=2),
                    "reason": "SQL statement appears dynamically constructed.",
                    "confidence": "HIGH"
                })
                continue

            if any(re.search(p, line) for p in self.sqli_exec_patterns):
                window = "\n".join(lines[max(0, i - 4):i])
                if ("SELECT" in window or "INSERT" in window or "UPDATE" in window or "DELETE" in window) and (
                    "f\"" in window or "f'" in window or ".format(" in window or "+" in window or "%" in window
                ):
                    findings.append({
                        "cwe": "CWE-89",
                        "type": "Potential SQL Injection",
                        "file": filename,
                        "line": i,
                        "column": 1,
                        "code": line.strip(),
                        "region": self.get_region(lines, i, window=2),
                        "reason": "Dynamic SQL appears to flow into execute().",
                        "confidence": "HIGH"
                    })
        return findings

    def detect_xss(self, lines: List[str], filename: str) -> List[Dict]:
        findings = []
        for i, line in enumerate(lines, start=1):
            if any(re.search(p, line) for p in self.xss_patterns):
                confidence = "MEDIUM"
                reason = "Potential unsafe HTML rendering."
                nearby = "\n".join(lines[max(0, i - 4):i + 1])
                if self._has_request_source_nearby(lines, i - 1) or "safe" in nearby.lower():
                    confidence = "HIGH"
                    reason = "HTML rendering appears influenced by request/user input or unsafe bypass."
                findings.append({
                    "cwe": "CWE-79",
                    "type": "Potential XSS",
                    "file": filename,
                    "line": i,
                    "column": 1,
                    "code": line.strip(),
                    "region": self.get_region(lines, i, window=2),
                    "reason": reason,
                    "confidence": confidence
                })
        return findings

    def detect_path_traversal(self, lines: List[str], filename: str) -> List[Dict]:
        findings = []
        for i, line in enumerate(lines, start=1):
            if any(re.search(p, line) for p in self.path_patterns):
                confidence = "MEDIUM"
                reason = "File/path operation detected."
                nearby = "\n".join(lines[max(0, i - 5):i + 1])
                if self._has_request_source_nearby(lines, i - 1) or "../" in nearby or "+" in line:
                    confidence = "HIGH"
                    reason = "File/path operation appears influenced by user input."
                findings.append({
                    "cwe": "CWE-22",
                    "type": "Potential Path Traversal",
                    "file": filename,
                    "line": i,
                    "column": 1,
                    "code": line.strip(),
                    "region": self.get_region(lines, i, window=2),
                    "reason": reason,
                    "confidence": confidence
                })
        return findings

    def _build_focus(self, findings: List[Dict]) -> List[str]:
        focus = set()
        for f in findings:
            if f["cwe"] == "CWE-918":
                focus.add("User-controlled URLs flowing into outbound HTTP requests")
            elif f["cwe"] == "CWE-89":
                focus.add("Dynamic SQL construction and execution")
            elif f["cwe"] == "CWE-79":
                focus.add("Unsafe HTML rendering and output encoding gaps")
            elif f["cwe"] == "CWE-22":
                focus.add("User-controlled file paths and directory traversal risk")
        return sorted(list(focus))


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python python_planner.py <python_file>")
        sys.exit(1)

    filepath = sys.argv[1]
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        code = f.read()

    planner = PythonStaticPlanner()
    result = planner.analyze(code, filename=filepath)
    print(json.dumps(result, indent=2))