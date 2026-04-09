import ast
import random
import string
from typing import Optional

from pydantic import BaseModel


# 1. OpenEnv Typed Models
class Observation(BaseModel):
    step: int
    vulnerability_type: str
    current_code: str
    linter_output: str


class Action(BaseModel):
    action_type: str  # e.g., "run_scan" or "submit_patch"
    patched_code: Optional[str] = ""


class Reward(BaseModel):
    value: float


class Info(BaseModel):
    error: Optional[str] = None


# AST Checkers for Robust Grading
def uses_os_getenv(code: str) -> bool:
    """
    Returns True if the code uses any safe environment-variable access pattern:
      - os.getenv("KEY")          -> ast.Call with Attribute attr='getenv'
      - os.environ.get("KEY")     -> ast.Call with chained Attribute: environ -> get
      - os.environ["KEY"]         -> ast.Subscript on os.environ
      - bare os.environ reference -> ast.Attribute with attr='environ'
    """
    try:
        tree = ast.parse(code)
        for node in ast.walk(tree):
            # Pattern 1: os.getenv(...) or getenv(...)
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Attribute) and func.attr == "getenv":
                    return True
                if isinstance(func, ast.Name) and func.id == "getenv":
                    return True
                # Pattern 2: os.environ.get(...) — chained call
                if (
                    isinstance(func, ast.Attribute)
                    and func.attr == "get"
                    and isinstance(func.value, ast.Attribute)
                    and func.value.attr == "environ"
                ):
                    return True
            # Pattern 3: os.environ["KEY"] — subscript access
            if isinstance(node, ast.Subscript):
                val = node.value
                if isinstance(val, ast.Attribute) and val.attr == "environ":
                    return True
            # Pattern 4: bare os.environ reference (e.g. env = os.environ)
            if isinstance(node, ast.Attribute) and node.attr == "environ":
                return True
    except SyntaxError:
        pass
    return False


def uses_parameterized_query(code: str) -> bool:
    try:
        tree = ast.parse(code)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # Simple heuristic mapping for typical execution paths
                if hasattr(node.func, "attr") and node.func.attr == "execute":
                    # length of args > 1 indicates query + params, or uses named keywords like parameters=...
                    if len(node.args) > 1 or (
                        node.keywords
                        and any(
                            k.arg in ("parameters", "params") for k in node.keywords
                        )
                    ):
                        return True
                    # Check if any arg is explicitly a tuple or dictionary, common in SQLite parameterization
                    for arg in node.args:
                        if isinstance(arg, ast.Tuple) or isinstance(arg, ast.Dict):
                            return True
    except SyntaxError:
        pass
    return False


def uses_safe_subprocess(code: str) -> bool:
    try:
        tree = ast.parse(code)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if hasattr(node.func, "attr") and node.func.attr in (
                    "run",
                    "Popen",
                    "call",
                    "check_call",
                    "check_output",
                ):
                    # Ensure shell=True is NOT passed
                    is_shell = False
                    for kw in node.keywords:
                        if (
                            kw.arg == "shell"
                            and isinstance(kw.value, ast.Constant)
                            and kw.value.value is True
                        ):
                            is_shell = True
                    if not is_shell:
                        # Ensure first argument is a list (args array)
                        if node.args and isinstance(node.args[0], ast.List):
                            return True
    except SyntaxError:
        pass
    return False


# 2. Environment Implementation
class VulnPatchEnv:
    def __init__(self, task="easy"):
        self.task = task
        self.step_count = 0
        self.done = False
        self.code = ""
        self.linter = ""
        self.target_secret = ""
        self.reset()

    def reset(self) -> Observation:
        random.seed(42)  # Fixed seed for reproducible baseline scores
        self.step_count = 0
        self.done = False
        self.linter = "Not run yet."

        # Dynamic variable generation prevents simple string memorization by the LLM
        if self.task == "easy":
            key_val = "sk-" + "".join(
                random.choices(string.ascii_uppercase + string.digits, k=16)
            )
            var_name = random.choice(
                ["API_KEY", "SECRET_KEY", "AUTH_TOKEN", "ACCESS_KEY"]
            )
            func_name = random.choice(["get_data", "fetch_resource", "load_user"])
            self.code = f"import os\n\ndef {func_name}():\n    {var_name} = '{key_val}'\n    return fetch({var_name})"
            self.target_secret = key_val

        elif self.task == "medium":
            table = random.choice(["users", "accounts", "employees", "orders"])
            field = random.choice(["name", "email", "username", "id"])
            self.code = f"import sqlite3\n\ndef get_{table}({field}):\n    query = f\"SELECT * FROM {table} WHERE {field}='{{{field}}}'\"\n    cursor.execute(query)"

        elif self.task == "hard":
            cmd = random.choice(["ping -c 4", "ls -l", "curl", "nmap"])
            self.code = f"import os\nimport subprocess\n\ndef run_util(user_arg):\n    os.system(f'{cmd} {{user_arg}}')"

        else:
            self.code = "Unknown task."
            self.target_secret = ""

        return self.state()

    def state(self) -> Observation:
        return Observation(
            step=self.step_count,
            vulnerability_type=self.task,
            current_code=self.code,
            linter_output=self.linter,
        )

    def step(self, action: Action) -> tuple[Observation, Reward, bool, Info]:
        self.step_count += 1
        reward_val = 0.0

        if action.action_type == "run_scan":
            self.linter = "SECURITY SCAN: Vulnerability detected. Fix hardcoded secrets, SQLi, or Command Injection."
            reward_val = 0.1  # Incremental progress signal

        elif action.action_type == "submit_patch":
            patched = action.patched_code if action.patched_code else ""

            # Hybrid AST/String Grading for robustness against formatting
            if self.task == "easy":
                if self.target_secret and self.target_secret not in patched:
                    reward_val += 0.5
                if uses_os_getenv(patched):
                    reward_val += 0.5

            elif self.task == "medium":
                if 'f"SELECT' not in patched and "f'SELECT" not in patched:
                    reward_val += 0.4
                if uses_parameterized_query(patched):
                    reward_val += 0.6
                elif "?" in patched or "%s" in patched:  # Fallback text format check
                    reward_val += 0.4

            elif self.task == "hard":
                if "os.system" not in patched:
                    reward_val += 0.3
                if uses_safe_subprocess(patched):
                    reward_val += 0.7
                elif (
                    "subprocess" in patched and "[" in patched and "]" in patched
                ):  # Fallback text format check
                    reward_val += 0.4

            self.done = True

        # Hard limit to prevent infinite loops (Penalize logic per OpenEnv spec requirement)
        if self.step_count >= 5 and not self.done:
            self.done = True
            reward_val -= 0.2

        # Clamp reward strictly within open interval (0, 1) — 0.0 and 1.0 are not allowed
        reward_val = min(max(reward_val, 0.01), 0.99)

        return self.state(), Reward(value=reward_val), self.done, Info()

    def close(self) -> None:
        """No-op cleanup method required by the OpenEnv spec."""
        pass
