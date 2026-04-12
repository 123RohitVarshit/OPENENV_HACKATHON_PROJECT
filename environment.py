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
                # Pattern 2: os.environ.get(...) or environ.get(...)
                if isinstance(func, ast.Attribute) and func.attr == "get":
                    if isinstance(func.value, ast.Attribute) and func.value.attr == "environ":
                        return True
                    if isinstance(func.value, ast.Name) and func.value.id == "environ":
                        return True
            # Pattern 3: os.environ["KEY"] or environ["KEY"]
            if isinstance(node, ast.Subscript):
                val = node.value
                if isinstance(val, ast.Attribute) and val.attr == "environ":
                    return True
                if isinstance(val, ast.Name) and val.id == "environ":
                    return True
            # Pattern 4: bare os.environ reference (e.g. env = os.environ)
            if isinstance(node, ast.Attribute) and node.attr == "environ":
                return True
            if isinstance(node, ast.Name) and node.id == "environ":
                return True
    except SyntaxError:
        pass
    return False


def uses_safe_yaml(code: str) -> bool:
    """
    Returns True if the agent securely parses YAML using safe_load.
    """
    try:
        tree = ast.parse(code)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Attribute) and func.attr == "safe_load":
                    return True
                if isinstance(func, ast.Name) and func.id == "safe_load":
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
                        # Ensure first argument is a list or a variable reference
                        if node.args:
                            arg0 = node.args[0]
                            if isinstance(arg0, (ast.List, ast.Name)):
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

        if self.task == "easy":
            key_val = "sk-" + "".join(
                random.choices(string.ascii_uppercase + string.digits, k=16)
            )
            # A real-looking build deployment script finding
            self.code = f"""import os
import requests

def upload_package_to_pypi(package_data):
    # Fallback legacy token (CVE-798 Supply Chain Leak)
    PYPI_API_TOKEN = '{key_val}'
    
    headers = {{"Authorization": f"Bearer {{PYPI_API_TOKEN}}"}}
    response = requests.post("https://upload.pypi.org/legacy/", data=package_data, headers=headers)
    return response.status_code
"""
            self.target_secret = key_val

        elif self.task == "medium":
            # Realistic yaml config loader
            self.code = """import yaml
import os

def load_project_config(config_path):
    \"\"\"Reads the project.yaml configuration file for the build properties.\"\"\"
    if not os.path.exists(config_path):
        return {}
    
    with open(config_path, 'r') as f:
        # Vulnerable to arbitrary code execution (CVE-502)
        config_data = yaml.load(f.read())
        
    return config_data
"""
            self.target_secret = ""

        elif self.task == "hard":
            self.code = """import os
import subprocess
from setuptools import setup, find_packages

# Example extracted from vulnerable setup.py / CI workflow
def run_pre_build_validation(repo_url):
    print("Running arbitrary validations before build...")
    # Vulnerable to command injection (CWE-78) via unsanitized strings
    os.system(f"git clone {repo_url} /tmp/repo_check")

setup(
    name="my_secure_package",
    version="1.0.0",
    packages=find_packages(),
)
"""
            self.target_secret = ""

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
            self.linter = "SECURITY SCAN (Supply Chain): Vulnerability detected. Fix hardcoded secrets, insecure deserialization (yaml), or CI command injection."
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
                if "yaml.load(" not in patched and "yaml.load (" not in patched:
                    reward_val += 0.3
                if uses_safe_yaml(patched):
                    reward_val += 0.7
                elif "yaml.safe_load" in patched or "safe_load" in patched:
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
