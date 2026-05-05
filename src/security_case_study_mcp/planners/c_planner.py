import re
import json
from typing import List, Dict


class CStaticPlanner:
    def __init__(self):
        self.patterns = {
            "CWE-120": {
                "type": "Classic Buffer Overflow",
                "patterns": [
                    r"\bstrcpy\s*\(",
                    r"\bstrcat\s*\(",
                    r"\bsprintf\s*\(",
                    r"\bvsprintf\s*\(",
                    r"\bgets\s*\(",
                    r'scanf\s*\(\s*".*%s.*"',
                ],
            },
            "CWE-125/787": {
                "type": "Out-of-bounds Read/Write",
                "patterns": [
                    r"\bmemcpy\s*\(",
                    r"\bmemmove\s*\(",
                    r"\bmemset\s*\(",
                    r"\w+\s*\[\s*\w+\s*\]",
                ],
            },
            "CWE-476": {
                "type": "Null Pointer Dereference",
                "patterns": [
                    r"(\w+)\s*=\s*(malloc|calloc|realloc)\s*\(",
                    r"(\w+)\s*=\s*fopen\s*\(",
                    r"\w+\s*\[\s*\w+\s*\]",
                ],
            },
            "CWE-680": {
                "type": "Integer Overflow to Buffer Overflow",
                "patterns": [
                    r"\bmalloc\s*\(\s*\w+\s*[\*\+]\s*\w+",
                    r"\bcalloc\s*\(\s*\w+\s*,\s*\w+",
                    r"\brealloc\s*\(\s*\w+\s*,\s*\w+\s*[\*\+]\s*\w+",
                ],
            },
        }

        self.alt_bound_names = [
            "length",
            "len",
            "remaining",
            "remain",
            "inputLen",
            "inputSz",
            "bufLen",
            "bufSz",
            "fieldLen",
            "fieldSz",
            "msgLen",
            "msgSz",
            "dataLen",
            "dataSz",
            "outLen",
            "outSz",
            "totalLen",
            "totalSz",
        ]

        self.sensitive_names = [
            "len",
            "length",
            "size",
            "sz",
            "count",
            "cnt",
            "index",
            "idx",
            "offset",
            "remaining",
            "remain",
            "avail",
            "available",
            "copysz",
            "copylen",
            "datasz",
            "datalen",
            "msgsz",
            "msglen",
            "totalsz",
            "totallen",
            "inputsz",
            "inputlen",
            "fieldsz",
            "fieldlen",
        ]

        self.arg_underflow_tokens = [
            "sz",
            "size",
            "len",
            "length",
            "offset",
            "remain",
            "remaining",
            "mac",
            "mac_size",
            "tag",
            "iv",
            "nonce",
            "header",
            "payload",
            "data",
            "msg",
            "input",
            "output",
            "auth",
        ]

    def get_region(self, lines: List[str], line_no: int, window: int = 2) -> Dict:
        start = max(1, line_no - window)
        end = min(len(lines), line_no + window)
        snippet = []
        for i in range(start, end + 1):
            snippet.append({"line": i, "text": lines[i - 1].rstrip()})
        return {
            "start_line": start,
            "end_line": end,
            "snippet": snippet,
        }

    def deduplicate_findings(self, findings: List[Dict]) -> List[Dict]:
        unique = []
        seen = set()
        for f in findings:
            key = (
                f.get("cwe"),
                f.get("type"),
                f.get("line"),
                f.get("code"),
            )
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def analyze(self, code: str, filename: str = "unknown.c") -> Dict:
        findings = []
        lines = code.splitlines()

        for cwe, info in self.patterns.items():
            for pattern in info["patterns"]:
                regex = re.compile(pattern)
                for i, line in enumerate(lines, start=1):
                    if regex.search(line):
                        findings.append(
                            {
                                "cwe": cwe,
                                "type": info["type"],
                                "file": filename,
                                "line": i,
                                "column": 1,
                                "code": line.strip(),
                                "region": self.get_region(lines, i, window=2),
                                "confidence": "MEDIUM",
                            }
                        )

        findings.extend(self.detect_null_deref_with_positions(lines, filename))
        findings.extend(self.detect_null_deref_in_function_args(lines, filename))
        findings.extend(self.detect_loop_bound_mismatch(lines, filename))
        findings.extend(self.detect_integer_underflow(lines, filename))
        findings.extend(self.detect_underflow_in_function_args(lines, filename))
        findings.extend(self.detect_signed_to_unsigned_size_issues(lines, filename))
        findings.extend(self.detect_raw_buffer_used_as_string(lines, filename))
        findings.extend(self.detect_integer_overflow(lines, filename))
        findings.extend(self.detect_off_by_one_heap_write(lines, filename))
        findings.extend(self.detect_pointer_offset_overflow(lines, filename))

        findings = self.deduplicate_findings(findings)

        return {
            "language": "C",
            "detected_issues": findings,
            "analysis_focus": self._build_focus(findings),
        }

    def detect_null_deref_with_positions(
        self, lines: List[str], filename: str
    ) -> List[Dict]:
        findings = []
        pointer_vars = set()

        for i, line in enumerate(lines, start=1):
            decl_match = re.search(r"\b(\w+)\s*\*\s*(\w+)", line)
            if decl_match:
                pointer_vars.add(decl_match.group(2))

        for i, line in enumerate(lines, start=1):
            deref_match = re.search(r"\b(\w+)\s*\[\s*0\s*\]", line)
            if deref_match:
                var = deref_match.group(1)
                if var in pointer_vars:
                    window_lines = lines[max(0, i - 6): i - 1]
                    null_checked = any(
                        re.search(
                            rf"if\s*\(\s*(!\s*{var}|{var}\s*==\s*NULL|{var}\s*!=\s*NULL)",
                            l,
                        )
                        for l in window_lines
                    )
                    if not null_checked:
                        findings.append(
                            {
                                "cwe": "CWE-476",
                                "type": "Potential Null Pointer Dereference",
                                "file": filename,
                                "line": i,
                                "column": 1,
                                "code": line.strip(),
                                "region": self.get_region(lines, i, window=2),
                                "confidence": "MEDIUM",
                            }
                        )

        return findings

    def detect_null_deref_in_function_args(
        self, lines: List[str], filename: str
    ) -> List[Dict]:
        findings = []

        api_patterns = [
            r"\bstrlen\s*\(\s*([A-Za-z_][A-Za-z0-9_>\-\.]*)\s*\)",
            r"\bstrnlen\s*\(\s*([A-Za-z_][A-Za-z0-9_>\-\.]*)\s*,",
            r"\bstrcmp\s*\(\s*([A-Za-z_][A-Za-z0-9_>\-\.]*)\s*,",
            r"\bstrncmp\s*\(\s*([A-Za-z_][A-Za-z0-9_>\-\.]*)\s*,",
            r"\bstrcpy\s*\(\s*[^,]+\s*,\s*([A-Za-z_][A-Za-z0-9_>\-\.]*)\s*\)",
            r"\bstrcat\s*\(\s*[^,]+\s*,\s*([A-Za-z_][A-Za-z0-9_>\-\.]*)\s*\)",
        ]

        for i, line in enumerate(lines, start=1):
            for pat in api_patterns:
                m = re.search(pat, line)
                if not m:
                    continue

                expr = m.group(1)

                window_lines = lines[max(0, i - 6):i]
                window_text = "\n".join(window_lines)

                checked = (
                    re.search(rf"if\s*\(\s*!?\s*{re.escape(expr)}\s*\)", window_text)
                    or re.search(rf"{re.escape(expr)}\s*!=\s*NULL", window_text)
                    or re.search(rf"{re.escape(expr)}\s*==\s*NULL", window_text)
                )

                if not checked:
                    findings.append(
                        {
                            "cwe": "CWE-476",
                            "type": "Potential Null Pointer Dereference in Function Argument",
                            "file": filename,
                            "line": i,
                            "column": 1,
                            "code": line.strip(),
                            "region": self.get_region(lines, i, window=2),
                            "reason": (
                                f"Expression '{expr}' is passed to a string API without a nearby NULL check."
                            ),
                            "confidence": "MEDIUM",
                        }
                    )

        return findings

    def detect_loop_bound_mismatch(
        self, lines: List[str], filename: str
    ) -> List[Dict]:
        findings = []

        loop_re = re.compile(
            r"for\s*\(\s*"
            r"(\w+)\s*=\s*(\w+)\s*\+\s*(\w+)\s*;\s*"
            r"\(\s*\1\s*-\s*\2\s*\)\s*<\s*(\w+)\s*;"
        )

        for i, line in enumerate(lines, start=1):
            m = loop_re.search(line)
            if not m:
                continue

            iterator, base, offset, bound = m.groups()

            start = max(0, i - 6)
            end = min(len(lines), i + 6)
            window_lines = lines[start:end]
            window_text = "\n".join(window_lines)

            alt_found = []
            for name in self.alt_bound_names:
                if name != bound and re.search(rf"\b{name}\b", window_text):
                    alt_found.append(name)

            if alt_found:
                findings.append(
                    {
                        "cwe": "CWE-125/787",
                        "candidate_cwes": ["CWE-125", "CWE-787", "CWE-119"],
                        "type": "Potential Loop Bound Mismatch",
                        "file": filename,
                        "line": i,
                        "column": 1,
                        "code": line.strip(),
                        "region": self.get_region(lines, i, window=3),
                        "reason": (
                            f"Loop iterates from '{base} + {offset}' and compares "
                            f"({iterator} - {base}) against '{bound}', while nearby "
                            f"alternative bound variable(s) also appear: {alt_found}"
                        ),
                        "confidence": "MEDIUM",
                    }
                )

        return findings

    def detect_integer_underflow(
        self, lines: List[str], filename: str
    ) -> List[Dict]:
        findings = []

        assign_sub_re = re.compile(
            r"^\s*(?:[A-Za-z_][A-Za-z0-9_\s\*]*\s+)?"
            r"(\w+)\s*=\s*\(?\s*([^;()]+?)\s*-\s*([^;()]+?)\s*\)?\s*;"
        )

        mem_sub_re = re.compile(
            r"\b(memcpy|memmove|memset)\s*\(\s*[^,]+\s*,\s*[^,]+\s*,\s*([^)]+-\s*[^)]+)\)"
        )

        for i, line in enumerate(lines, start=1):
            m = assign_sub_re.search(line)
            if m:
                lhs, a, b = m.groups()
                lhs_lower = lhs.lower()

                suspicious_name = any(name in lhs_lower for name in self.sensitive_names)

                window_lines = lines[max(0, i - 6):i]
                window_text = "\n".join(window_lines)

                guarded = (
                    re.search(rf"\b{re.escape(a)}\s*>=\s*{re.escape(b)}\b", window_text)
                    or re.search(rf"\b{re.escape(b)}\s*<=\s*{re.escape(a)}\b", window_text)
                    or re.search(rf"\b{re.escape(a)}\s*>\s*0\b", window_text)
                    or re.search(rf"\b{re.escape(a)}\s*!=\s*0\b", window_text)
                )

                if suspicious_name and not guarded:
                    findings.append(
                        {
                            "cwe": "CWE-191",
                            "type": "Potential Integer Underflow (Wrap or Wraparound)",
                            "file": filename,
                            "line": i,
                            "column": 1,
                            "code": line.strip(),
                            "region": self.get_region(lines, i, window=2),
                            "reason": (
                                f"Subtraction '{a} - {b}' assigned to '{lhs}' without nearby guard "
                                f"ensuring the left operand is large enough."
                            ),
                            "confidence": "MEDIUM",
                        }
                    )

            m2 = mem_sub_re.search(line)
            if m2:
                func, expr = m2.groups()

                window_lines = lines[max(0, i - 6):i]
                window_text = "\n".join(window_lines)

                guarded = bool(re.search(r"(<=|>=|<|>)", window_text))

                if not guarded:
                    findings.append(
                        {
                            "cwe": "CWE-191",
                            "candidate_cwes": ["CWE-125", "CWE-787", "CWE-119"],
                            "type": "Potential Integer Underflow in Size Calculation",
                            "file": filename,
                            "line": i,
                            "column": 1,
                            "code": line.strip(),
                            "region": self.get_region(lines, i, window=2),
                            "reason": (
                                f"Subtraction expression '{expr.strip()}' is used as the size argument "
                                f"to {func} without nearby validation."
                            ),
                            "confidence": "MEDIUM",
                        }
                    )

        return findings

    def detect_underflow_in_function_args(
        self, lines: List[str], filename: str
    ) -> List[Dict]:
        findings = []

        chained_sub_re = re.compile(r"([^\s,()]+(?:\s*-\s*[^\s,()]+){2,})")

        for i in range(len(lines)):
            start = i
            end = min(i + 8, len(lines))
            chunk_lines = lines[start:end]
            chunk = " ".join(l.strip() for l in chunk_lines if l.strip())

            if "-" not in chunk:
                continue

            call_like = "(" in chunk and "," in chunk
            if not call_like:
                continue

            m = chained_sub_re.search(chunk)
            if not m:
                continue

            expr = m.group(1)
            lowered = expr.lower()

            token_hits = [tok for tok in self.arg_underflow_tokens if tok in lowered]
            if not token_hits:
                continue

            prev_window = "\n".join(lines[max(0, i - 6):i])
            guarded = bool(re.search(r"(<=|>=)", prev_window))

            if not guarded:
                findings.append(
                    {
                        "cwe": "CWE-191",
                        "candidate_cwes": ["CWE-125", "CWE-787", "CWE-119"],
                        "type": "Potential Integer Underflow in Function Argument",
                        "file": filename,
                        "line": i + 1,
                        "column": 1,
                        "code": lines[i].strip(),
                        "region": self.get_region(lines, i + 1, window=3),
                        "reason": (
                            f"Chained subtraction '{expr.strip()}' appears inside a function-call "
                            f"argument list without nearby lower-bound validation; detected tokens: {token_hits}"
                        ),
                        "confidence": "MEDIUM",
                    }
                )

        return findings

    def detect_signed_to_unsigned_size_issues(self, lines: List[str], filename: str) -> List[Dict]:
        findings = []

        signed_assign_re = re.compile(
            r"^\s*(?:const\s+|static\s+|volatile\s+|register\s+)*"
            r"(?:signed\s+)?(?:int|long|short|ssize_t)\s+(\w+)\s*=\s*.+;"
        )

        cast_sink_re = re.compile(
            r"\b(memcpy|memmove|memset|malloc|calloc|realloc)\s*\([^;]*?\(\s*size_t\s*\)\s*(\w+)",
            re.DOTALL
        )

        signed_vars = {}
        for i, line in enumerate(lines, start=1):
            m = signed_assign_re.search(line)
            if m:
                signed_vars[m.group(1)] = i

        full_text = "\n".join(lines)

        for m in cast_sink_re.finditer(full_text):
            func, var = m.groups()

            if var not in signed_vars:
                continue

            line_no = full_text.count("\n", 0, m.start()) + 1

            start_line = max(1, signed_vars[var] - 1)
            end_line = line_no
            window_lines = lines[start_line - 1:end_line]
            window_text = "\n".join(window_lines)

            has_upper_check = bool(
                re.search(rf"\bif\s*\(\s*{var}\s*>\s*", window_text) or
                re.search(rf"\bif\s*\(\s*{var}\s*>=\s*", window_text) or
                re.search(rf"\b{var}\s*=\s*\(?\s*.*sizeof", window_text)
            )

            has_lower_check = bool(
                re.search(rf"\bif\s*\(\s*{var}\s*<\s*0\s*\)", window_text) or
                re.search(rf"\bif\s*\(\s*{var}\s*<=\s*0\s*\)", window_text) or
                re.search(rf"\bif\s*\(\s*{var}\s*>\s*0\s*\)", window_text) or
                re.search(rf"\bif\s*\(\s*{var}\s*>=\s*0\s*\)", window_text) or
                re.search(rf"\b{var}\s*=\s*0\s*;", window_text)
            )

            if has_upper_check and not has_lower_check:
                findings.append({
                    "cwe": "CWE-191",
                    "candidate_cwes": ["CWE-787", "CWE-125", "CWE-119"],
                    "type": "Potential Integer Underflow / Signed-to-Unsigned Size Conversion",
                    "file": filename,
                    "line": line_no,
                    "column": 1,
                    "code": lines[line_no - 1].strip(),
                    "region": self.get_region(lines, line_no, window=3),
                    "reason": (
                        f"Signed variable '{var}' is cast to size_t in {func} after upper-bound "
                        f"validation but without nearby lower-bound validation."
                    ),
                    "confidence": "MEDIUM"
                })

        return findings

    def detect_raw_buffer_used_as_string(self, lines: List[str], filename: str) -> List[Dict]:
        findings = []

        raw_buffer_sources = [
            r"(\w+)\s*=\s*\(?char\s*\*\)?\s*nng_msg_body\s*\(",
            r"(\w+)\s*=\s*nng_msg_body\s*\(",
        ]

        string_sinks = [
            r"cJSON_Parse\s*\(\s*(\w+)\s*\)",
            r"strlen\s*\(\s*(\w+)\s*\)",
            r"strcmp\s*\(\s*(\w+)\s*,",
            r'printf\s*\(\s*".*%s.*"\s*,\s*(\w+)\s*\)',
        ]

        source_vars = {}

        for i, line in enumerate(lines, start=1):
            for pat in raw_buffer_sources:
                m = re.search(pat, line)
                if m:
                    source_vars[m.group(1)] = i

        for i, line in enumerate(lines, start=1):
            for pat in string_sinks:
                m = re.search(pat, line)
                if not m:
                    continue

                var = m.group(1)
                if var not in source_vars:
                    continue

                start = max(0, source_vars[var] - 1)
                end = min(len(lines), i + 2)
                window = "\n".join(lines[start:end])

                has_len_check = "nng_msg_len" in window
                has_copy = "memcpy" in window or "strncpy" in window
                has_null_term = re.search(rf"{var}\s*\[.*\]\s*=\s*'\\0'", window)

                if not (has_len_check and (has_copy or has_null_term)):
                    findings.append({
                        "cwe": "CWE-125",
                        "candidate_cwes": ["CWE-170", "CWE-20"],
                        "type": "Potential Raw Buffer Used as Null-Terminated String",
                        "file": filename,
                        "line": i,
                        "column": 1,
                        "code": line.strip(),
                        "region": self.get_region(lines, i, window=3),
                        "reason": (
                            f"Variable '{var}' appears to come from a raw message body API "
                            f"and is later passed to a string parser without clear length-based "
                            f"copying and null termination."
                        ),
                        "confidence": "MEDIUM"
                    })

        return findings

    def detect_integer_overflow(self, lines: List[str], filename: str) -> List[Dict]:
        findings = []

        for i, line in enumerate(lines, start=1):
            stripped = line.strip()

            if "if" not in stripped:
                continue
            if "(" not in stripped:
                continue

            suspicious = False
            reason = None

            if "(uint64_t)" in stripped or "(size_t)" in stripped or "(uint32_t)" in stripped:
                if "*" in stripped or "+" in stripped or "<<" in stripped:
                    suspicious = True
                    reason = (
                        "Condition contains arithmetic with an integer cast; "
                        "overflow may occur before or during the comparison."
                    )
            elif "+" in stripped and "*" in stripped:
                suspicious = True
                reason = (
                    "Condition contains combined addition and multiplication, "
                    "which may overflow before comparison."
                )
            elif "<<" in stripped:
                suspicious = True
                reason = "Condition contains left-shift arithmetic, which may overflow."

            if suspicious:
                findings.append({
                    "cwe": "CWE-190",
                    "candidate_cwes": ["CWE-680", "CWE-119", "CWE-787"],
                    "type": "Potential Integer Overflow or Wraparound in Condition",
                    "file": filename,
                    "line": i,
                    "column": 1,
                    "code": stripped,
                    "region": self.get_region(lines, i, window=2),
                    "reason": reason,
                    "confidence": "MEDIUM"
                })

        return findings
    def detect_off_by_one_heap_write(self, lines: List[str], filename: str) -> List[Dict]:
        findings = []

        alloc_vars = {}

        malloc_re = re.compile(
            r'^\s*(\w+)\s*=\s*\([^)]*\)\s*malloc\s*\(\s*([^)]+?)\s*\)\s*;|^\s*(\w+)\s*=\s*malloc\s*\(\s*([^)]+?)\s*\)\s*;'
        )

        ptr_write_re = re.compile(
            r'\*\s*\(\s*(\w+)\s*\+\s*([^)]+?)\s*\)\s*='
        )

        index_write_re = re.compile(
            r'(\w+)\s*\[\s*([^\]]+?)\s*\]\s*='
        )

        for i, line in enumerate(lines, start=1):
            m = malloc_re.search(line)
            if m:
                var = m.group(1) or m.group(3)
                size_expr = m.group(2) or m.group(4)
                if var and size_expr:
                    alloc_vars[var] = (size_expr.strip(), i)

        for i, line in enumerate(lines, start=1):
            for regex, kind in [(ptr_write_re, "pointer"), (index_write_re, "index")]:
                m = regex.search(line)
                if not m:
                    continue

                var, idx_expr = m.group(1).strip(), m.group(2).strip()
                if var not in alloc_vars:
                    continue

                size_expr, alloc_line = alloc_vars[var]

                if idx_expr == size_expr:
                    findings.append({
                        "cwe": "CWE-787",
                        "candidate_cwes": ["CWE-193", "CWE-119"],
                        "type": "Potential Off-by-One Heap Write",
                        "file": filename,
                        "line": i,
                        "column": 1,
                        "code": line.strip(),
                        "region": self.get_region(lines, i, window=3),
                        "reason": (
                            f"Variable '{var}' is allocated with size '{size_expr}' "
                            f"but later written at offset/index '{idx_expr}', which is one past "
                            f"the last valid position."
                        ),
                        "confidence": "HIGH",
                    })

        return findings
    def detect_pointer_offset_overflow(self, lines: List[str], filename: str) -> List[Dict]:
        findings = []

        ptr_offset_patterns = [
            re.compile(r'^\s*(\w+)\s*\+=\s*([A-Za-z_][A-Za-z0-9_]*)\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*;'),
            re.compile(r'^\s*(\w+)\s*=\s*\(?[^;]*\)?\s*(\w+)\s*\+\s*([A-Za-z_][A-Za-z0-9_]*)\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*;')
        ]

        for i, line in enumerate(lines, start=1):
            stripped = line.strip()

            for pat in ptr_offset_patterns:
                m = pat.search(stripped)
                if not m:
                    continue

                if len(m.groups()) == 3:
                    ptr, a, b = m.groups()
                    expr = f"{a} * {b}"
                else:
                    ptr, base, a, b = m.groups()
                    expr = f"{a} * {b}"

                window_lines = lines[max(0, i - 6): min(len(lines), i + 6)]
                window_text = "\n".join(window_lines)

                has_guard = bool(
                    re.search(rf'\b{re.escape(a)}\s*<=\s*', window_text) or
                    re.search(rf'\b{re.escape(b)}\s*<=\s*', window_text) or
                    re.search(rf'\bsize_t\b', window_text) or
                    re.search(rf'\buint64_t\b', window_text) or
                    re.search(rf'\bptrdiff_t\b', window_text)
                )

                used_after = bool(
                    re.search(rf'\bmemcpy\s*\([^;]*\b{ptr}\b', window_text) or
                    re.search(rf'\bmemset\s*\([^;]*\b{ptr}\b', window_text) or
                    re.search(rf'\b{ptr}\s*\[', window_text) or
                    re.search(rf'\*\s*{ptr}\b', window_text)
                )

                if not has_guard:
                    findings.append({
                        "cwe": "CWE-190",
                        "candidate_cwes": ["CWE-787", "CWE-125", "CWE-119"],
                        "type": "Potential Integer Overflow in Pointer Offset Calculation",
                        "file": filename,
                        "line": i,
                        "column": 1,
                        "code": stripped,
                        "region": self.get_region(lines, i, window=3),
                        "reason": (
                            f"Pointer '{ptr}' is advanced using multiplicative offset '{expr}', "
                            f"which may overflow and lead to invalid memory access."
                        ),
                        "confidence": "MEDIUM" if used_after else "LOW",
                    })

        return findings

    def _build_focus(self, findings: List[Dict]) -> List[str]:
        focus = set()
        for f in findings:
            if f["cwe"] == "CWE-120":
                focus.add("Unsafe string handling and fixed-size buffers")
            elif f["cwe"] == "CWE-125/787":
                focus.add("Array bounds and memory copy size validation")
            elif f["cwe"] == "CWE-476":
                focus.add("NULL checks before pointer dereference")
            elif f["cwe"] == "CWE-680":
                focus.add("Integer overflow in memory allocation calculations")
            elif f["cwe"] == "CWE-191":
                focus.add("Integer subtraction safety and wraparound/underflow validation")
            elif f["cwe"] == "CWE-125":
                focus.add("Raw buffer boundaries and safe string handling")
            elif f["cwe"] == "CWE-190":
                focus.add("Integer arithmetic overflow and wraparound in size and condition logic")
                focus.add("Integer arithmetic overflow and wraparound in size, index, and pointer-offset logic")

            if f.get("type") == "Potential Loop Bound Mismatch":
                focus.add("Loop boundary consistency and subrange bound validation")

            elif f["cwe"] == "CWE-787":
                focus.add("Heap/array write bounds and off-by-one write validation")

        return sorted(list(focus))


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python c_planner.py <c_file>")
        sys.exit(1)

    filepath = sys.argv[1]
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        code = f.read()

    planner = CStaticPlanner()
    result = planner.analyze(code, filename=filepath)
    print(json.dumps(result, indent=2))