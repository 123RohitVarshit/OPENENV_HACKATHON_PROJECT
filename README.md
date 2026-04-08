# Vuln-Patch-Env

A real-world OpenEnv environment for training and evaluating AI agents on automated code vulnerability detection and patching.

---

## Overview

Vuln-Patch-Env simulates the task of **Static Application Security Testing (SAST) auto-remediation** — a genuine problem that security engineering teams solve daily. Given a snippet of Python code containing a known vulnerability, an agent must identify and patch the vulnerability without breaking the existing functionality.

The environment exposes three tasks of increasing difficulty, covering three of the most common vulnerability classes found in real-world codebases:

- **Hardcoded Secrets** (CWE-798)
- **SQL Injection via f-strings** (CWE-89)
- **Command Injection via os.system** (CWE-78)

The environment is fully compliant with the [OpenEnv](https://huggingface.co/openenv) specification and is designed to be used as a benchmark for evaluating LLM-based security agents.

---

## Motivation

Vulnerability remediation is a task that organizations spend significant engineering resources on. Automated patching tools exist but are largely rule-based and brittle. Training RL or LLM agents on a structured environment like this one opens the door to agents that can:

- Understand code semantics, not just surface patterns
- Generalize across variable names, table names, and command structures
- Learn to use safe APIs (parameterized queries, subprocess with argument lists) as a matter of policy

This environment fills a gap in the OpenEnv ecosystem by providing a **code security domain** benchmark with rigorous, AST-based grading that rewards only structurally correct fixes — not superficial string changes.

---

## Environment Specification

### OpenEnv Compliance

| Interface | Implementation |
|---|---|
| `reset()` | Returns initial `Observation`. Resets step counter, generates fresh vulnerable code. |
| `step(action)` | Returns `(Observation, Reward, done: bool, Info)` |
| `state()` | Returns current `Observation` without advancing the episode |
| `close()` | No-op cleanup method satisfying the OpenEnv spec |
| Typed models | `Observation`, `Action`, `Reward`, `Info` all defined as Pydantic models |
| `openenv.yaml` | Present at project root with name, version, entrypoint, and task list |

---

## Data Models

### Observation

Returned by `reset()`, `step()`, and `state()`.

| Field | Type | Description |
|---|---|---|
| `step` | `int` | Current step index within the episode (starts at 0) |
| `vulnerability_type` | `str` | Task identifier: `"easy"`, `"medium"`, or `"hard"` |
| `current_code` | `str` | The Python source code containing the vulnerability to be fixed |
| `linter_output` | `str` | Output from the security scanner. `"Not run yet."` until a scan is performed |

### Action

Submitted by the agent on each step.

| Field | Type | Required | Description |
|---|---|---|---|
| `action_type` | `str` | Always | Either `"run_scan"` or `"submit_patch"` |
| `patched_code` | `str` | Only for `"submit_patch"` | The complete fixed Python code as a string |

### Reward

| Field | Type | Description |
|---|---|---|
| `value` | `float` | Scalar reward in the range `[0.0, 1.0]` |

### Info

| Field | Type | Description |
|---|---|---|
| `error` | `str` or `None` | Environment-level error message, if any |

---

## Action Space

The agent has exactly two possible action types per step:

**1. `run_scan`**
Triggers the security linter. Returns a hint in the `linter_output` field of the next observation. Grants a small reward (`+0.1`) as a partial progress signal, encouraging the agent to gather information before patching.

**2. `submit_patch`**
Submits the agent's proposed fix via the `patched_code` field. The environment grades the patch using a hybrid AST + string analysis grader and returns a reward between `0.0` and `1.0`. The episode ends immediately upon submission.

---

## Observation Space

The agent receives a structured JSON observation on every step containing:

- The **current step index** so the agent can manage its budget
- The **vulnerability type** so the agent knows what class of problem it is solving
- The **current source code** — the same vulnerable snippet on every step (the environment does not modify the code between steps)
- The **linter output** — populated only after `run_scan` is called, providing a natural-language hint about the vulnerability class

---

## Tasks and Difficulty

### Task 1 — Easy: Hardcoded Secrets (CWE-798)

**Objective:** Remove a hardcoded API key from the source code and replace it with a call to `os.getenv()` or an equivalent safe environment-variable access pattern.

**Example vulnerable code generated:**
```python
import os

def fetch_resource():
    ACCESS_KEY = 'sk-A7FX29KQBR1NWLTZ'
    return fetch(ACCESS_KEY)
```

**Expected fix:**
```python
import os

def fetch_resource():
    ACCESS_KEY = os.getenv('ACCESS_KEY')
    return fetch(ACCESS_KEY)
```

**Grading breakdown:**
| Condition | Reward |
|---|---|
| Hardcoded secret string is absent from the patched code | +0.5 |
| Code uses a safe env-var access pattern (AST-verified) | +0.5 |
| **Maximum total** | **1.0** |

The grader accepts all of the following valid patterns via AST analysis:
- `os.getenv("KEY")`
- `os.environ.get("KEY")`
- `os.environ["KEY"]`
- Any bare reference to `os.environ`

---

### Task 2 — Medium: SQL Injection via f-strings (CWE-89)

**Objective:** Replace an f-string SQL query with a parameterized query to prevent SQL injection.

**Example vulnerable code generated:**
```python
import sqlite3

def get_users(name):
    query = f"SELECT * FROM users WHERE name='{name}'"
    cursor.execute(query)
```

**Expected fix:**
```python
import sqlite3

def get_users(name):
    query = "SELECT * FROM users WHERE name=?"
    cursor.execute(query, (name,))
```

**Grading breakdown:**
| Condition | Reward |
|---|---|
| f-string SQL construction is absent from patched code | +0.4 |
| `cursor.execute()` is called with a parameter argument (AST-verified) | +0.6 |
| Fallback: patch contains `?` or `%s` placeholder (string check) | +0.4 (instead of +0.6) |
| **Maximum total** | **1.0** |

---

### Task 3 — Hard: Command Injection via os.system (CWE-78)

**Objective:** Replace an `os.system()` call that passes unsanitized user input with a `subprocess.run()` call using a separated argument list, which prevents shell injection.

**Example vulnerable code generated:**
```python
import os
import subprocess

def run_util(user_arg):
    os.system(f'ping -c 4 {user_arg}')
```

**Expected fix:**
```python
import subprocess

def run_util(user_arg):
    subprocess.run(["ping", "-c", "4", user_arg])
```

**Grading breakdown:**
| Condition | Reward |
|---|---|
| `os.system` is absent from the patched code | +0.3 |
| `subprocess.run()` (or equivalent) is called with a list argument and no `shell=True` (AST-verified) | +0.7 |
| Fallback: patch contains `subprocess` with list brackets (string check) | +0.4 (instead of +0.7) |
| **Maximum total** | **1.0** |

---

## Reward Function Design

The reward function is designed to provide **meaningful signal over the full trajectory**, not just at episode end.

| Event | Reward | Rationale |
|---|---|---|
| `run_scan` action | +0.1 | Encourages information gathering before patching |
| Correct patch (full credit) | +1.0 | Agent removed the vulnerability and used the correct safe API |
| Partial patch (fallback) | +0.4 to +0.8 | Agent improved security but did not use the ideal pattern |
| Reaching step 5 without completing | -0.2 | Penalizes agents that loop without making progress |
| All rewards | Clamped to `[0.0, 1.0]` | Strict compliance with OpenEnv spec |

An episode ends when the agent calls `submit_patch` or when the step count reaches 5 (whichever comes first).

---

## Grading Methodology

A key design decision in this environment is the use of **Python's Abstract Syntax Tree (AST) module** for grading, rather than simple string matching or regex. This makes the grader:

- **Robust to formatting differences** — whitespace, line breaks, and quote style do not affect the grade
- **Semantically accurate** — a patch is only credited if the correct API is actually *called* in the code, not just mentioned in a comment
- **Resistant to false positives** — for example, `subprocess.run(..., shell=True)` is explicitly detected and rejected even though it contains `subprocess`

Each grader function (`uses_os_getenv`, `uses_parameterized_query`, `uses_safe_subprocess`) parses the submitted code into an AST and walks the node tree to verify the structural correctness of the fix. All graders fall back to string-based checks if the AST check is inconclusive, ensuring partial credit is awarded for genuinely improved but imperfect patches.

---

## Dynamic Code Generation

To prevent an LLM agent from memorizing fixed vulnerable snippets, the environment **generates code dynamically** on each `reset()` call by randomly selecting from pools of variable names, function names, table names, SQL fields, and shell commands. A fixed random seed (`seed=42`) is applied at the start of each `reset()` to ensure that baseline scores are fully reproducible across runs.

---

## Episode Lifecycle

```
reset(task)
    |
    v
Observation (step=0, vulnerable code, linter="Not run yet.")
    |
    v
Agent calls run_scan         --> reward=0.1, linter hint populated
    |
    v
Agent calls submit_patch     --> grader runs, reward=0.0–1.0, done=True
    |
    v
[END] logged, episode complete
```

Maximum steps per episode: **5**. If the agent does not submit a patch within 5 steps, the episode is forcibly ended with a `-0.2` penalty.

---

## Baseline Inference Script

The `inference.py` script runs a full three-task evaluation loop using any OpenAI-compatible LLM endpoint.

**Required environment variables:**

| Variable | Description | Default |
|---|---|---|
| `HF_TOKEN` | Hugging Face API token (or any OpenAI-compatible API key) | None (required) |
| `MODEL_NAME` | Model identifier to use for inference | `meta-llama/Llama-3.3-70B-Instruct` |
| `API_BASE_URL` | Base URL for the OpenAI-compatible inference endpoint | `https://router.huggingface.co/v1` |

**Running the baseline:**
```bash
export HF_TOKEN="your_hf_token_here"
export MODEL_NAME="meta-llama/Llama-3.3-70B-Instruct"
export API_BASE_URL="https://router.huggingface.co/v1"

python inference.py
```

**Expected stdout format:**
```
[START] task=easy env=vuln-patch-env model=meta-llama/Llama-3.3-70B-Instruct
[STEP] step=1 action=run_scan() reward=0.10 done=false error=null
[STEP] step=2 action=submit_patch() reward=1.00 done=true error=null
[END] success=true steps=2 score=1.00 rewards=0.10,1.00

[START] task=medium env=vuln-patch-env model=meta-llama/Llama-3.3-70B-Instruct
[STEP] step=1 action=submit_patch() reward=1.00 done=true error=null
[END] success=true steps=1 score=1.00 rewards=1.00

[START] task=hard env=vuln-patch-env model=meta-llama/Llama-3.3-70B-Instruct
[STEP] step=1 action=run_scan() reward=0.10 done=false error=null
[STEP] step=2 action=submit_patch() reward=1.00 done=true error=null
[END] success=true steps=2 score=1.00 rewards=0.10,1.00
```

**Baseline scores (Llama-3.3-70B-Instruct, temperature=0.0):**

| Task | Expected Score |
|---|---|
| easy | 1.00 |
| medium | >= 0.80 |
| hard | >= 0.80 |

---

## REST API Reference

The environment is served as a FastAPI application. All endpoints are available once the server is running.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Health check, returns server status |
| `GET` | `/health` | Returns `{"status": "healthy"}` — required by `openenv validate` |
| `GET` | `/metadata` | Returns environment name, description, version, and task list |
| `GET` | `/schema` | Returns JSON schemas for `Action`, `Observation`, and state |
| `POST` | `/mcp` | Minimal MCP (Model Context Protocol) endpoint — JSON-RPC 2.0 |
| `POST` | `/reset` | Resets the environment. Accepts `{"task": "easy" | "medium" | "hard"}` |
| `POST` | `/step` | Takes one step. Accepts an `Action` object as JSON body |
| `GET` | `/state` | Returns the current observation without advancing the episode |

**Example: Reset to the hard task**
```bash
curl -X POST http://localhost:7860/reset \
  -H "Content-Type: application/json" \
  -d '{"task": "hard"}'
```

**Example: Submit a patch**
```bash
curl -X POST http://localhost:7860/step \
  -H "Content-Type: application/json" \
  -d '{"action_type": "submit_patch", "patched_code": "import subprocess\n\ndef run_util(user_arg):\n    subprocess.run([\"ping\", \"-c\", \"4\", user_arg])"}'
```

---

## Project Structure

```
vuln-patch-env/
|
|-- server/
|   |-- __init__.py        # Exports the FastAPI app
|   +-- app.py             # FastAPI server with all OpenEnv-required endpoints
|
|-- environment.py         # Core environment: Pydantic models, AST graders, VulnPatchEnv class
|-- inference.py           # Baseline inference script using OpenAI-compatible client
|-- server.py              # Root-level entry point (re-exports server/app.py)
|-- openenv.yaml           # OpenEnv metadata declaration
|-- pyproject.toml         # Python package configuration
|-- requirements.txt       # Pinned dependencies
|-- Dockerfile             # Container definition for Hugging Face Spaces deployment
|-- README.md              # This file
+-- .gitignore
```

---

## Setup and Local Usage

**1. Clone the repository and install dependencies:**
```bash
git clone https://github.com/YOUR_USERNAME/vuln-patch-env.git
cd vuln-patch-env
pip install -r requirements.txt
```

**2. Start the server locally:**
```bash
uvicorn server.app:app --host 0.0.0.0 --port 7860
```

**3. Validate the OpenEnv spec compliance:**
```bash
openenv validate .
```

**4. Use the environment directly in Python:**
```python
from environment import VulnPatchEnv, Action

# Run the easy task
env = VulnPatchEnv(task="easy")
obs = env.reset()
print(obs.current_code)

# Get a hint
obs, reward, done, info = env.step(Action(action_type="run_scan"))
print(obs.linter_output)

# Submit a patch
patched = obs.current_code.replace("ACCESS_KEY = 'sk-...'", "ACCESS_KEY = os.getenv('ACCESS_KEY')")
obs, reward, done, info = env.step(Action(action_type="submit_patch", patched_code=patched))
print(f"Reward: {reward.value}")

env.close()
```

---

## Docker

**Build and run locally:**
```bash
docker build -t vuln-patch-env .
docker run -p 7860:7860 vuln-patch-env
```

The server will be available at `http://localhost:7860`.

---

## Dependencies

| Package | Version | Purpose |
|---|---|---|
| `openai` | 2.30.0 | OpenAI-compatible client for inference script |
| `pydantic` | 2.12.5 | Typed data models for Observation, Action, Reward, Info |
| `fastapi` | 0.135.3 | REST API server |
| `uvicorn` | 0.44.0 | ASGI server for FastAPI |
| `openenv-core` | 0.2.3 | OpenEnv spec utilities and validation |
| `python-dotenv` | 1.2.2 | Environment variable loading from `.env` files
