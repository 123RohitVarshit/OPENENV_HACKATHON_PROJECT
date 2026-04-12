---
title: Vuln-Patch-Env
emoji: 🛡️
colorFrom: red
colorTo: blue
sdk: docker
app_port: 7860
pinned: false
tags:
  - openenv
  - reinforcement-learning
  - code-security
  - supply-chain
  - vulnerability-patching
---

# Vuln-Patch-Env (Supply Chain Security Edition)

A real-world OpenEnv environment for training and evaluating AI agents on automated **Supply Chain vulnerability detection and patching**.

---

## Overview

Vuln-Patch-Env simulates the critical task of **Software Composition Analysis (SCA) & Supply Chain auto-remediation**. Given a snippet of Python code derived from real historical CVEs, an agent must identify and securely patch the vulnerability without breaking the existing functionality.

The environment exposes three tasks of increasing difficulty, covering three of the most devastating supply chain vulnerability classes found in the open-source ecosystem:

- **Task 1: Hardcoded Prominent Secrets** (CWE-798) — Inspired by real leaks in CI scripts (e.g., Flask-AppBuilder CVE-2023-30861)
- **Task 2: Insecure Config Deserialization** (CWE-502) — Derived from the notorious PyYAML supply chain flaws (CVE-2017-18342 / CVE-2020-14343)
- **Task 3: CI/CD Build Command Injection** (CWE-78) — Derived from unsanitized build script arguments like `youtube-dl` (CVE-2020-15366)

The environment is fully compliant with the [OpenEnv](https://huggingface.co/openenv) specification and is designed to be used as a benchmark for evaluating LLM-based security agents.

> **Security Disclaimer**: The vulnerable code snippets in this repository are strictly educational and inert. They are hardcoded as plain strings and are **never** actually executed or evaluated (`eval`) by the environment software. Furthermore, they use sanitized placeholder tokens and benign paths, ensuring that hosting or running this environment locally poses absolutely zero risk to your machine.

---

## Motivation

Supply chain attacks are increasingly targeting developer infrastructure, with attackers often exploiting hardcoded tokens, unsanitized build scripts, or outdated deserialization methods to achieve Remote Code Execution (RCE). Automated patching tools exist but are largely rule-based and brittle. Training RL or LLM agents on a structured environment like this one opens the door to agents that can:

- Understand code semantics, not just surface patterns
- Generalize across variable names, framework abstractions, and build systems
- Learn to use safe APIs (`os.getenv`, `yaml.safe_load`, `subprocess.run` list execution) as a matter of strict policy

This environment fills a gap in the OpenEnv ecosystem by providing a **supply chain security domain** benchmark with rigorous, AST-based grading that rewards only structurally correct fixes — not superficial string changes.

---

## Environment Specification

### OpenEnv Compliance

| Interface | Implementation |
|---|---|
| `reset()` | Returns initial `Observation`. Resets step counter, generates the real-world vulnerable codebase snippet. |
| `step(action)` | Returns `(Observation, Reward, done: bool, Info)` |
| `state()` | Returns current `Observation` without advancing the episode |
| `close()` | No-op cleanup method satisfying the OpenEnv spec |
| Typed models | `Observation`, `Action`, `Reward`, `Info` all defined as Pydantic models |

---

## Data Models

### Observation
Returned by `reset()`, `step()`, and `state()`.

| Field | Type | Description |
|---|---|---|
| `step` | `int` | Current step index within the episode (starts at 0) |
| `vulnerability_type` | `str` | Task identifier: `"easy"`, `"medium"`, or `"hard"` |
| `current_code` | `str` | The authentic Python source code containing the vulnerability to be fixed |
| `linter_output` | `str` | Output from the SCA scanner. `"Not run yet."` until a scan is performed |

### Action
Submitted by the agent on each step.

| Field | Type | Required | Description |
|---|---|---|---|
| `action_type` | `str` | Always | Either `"run_scan"` or `"submit_patch"` |
| `patched_code` | `str` | Only for `"submit_patch"` | The complete fixed Python code as a string |

### Reward

| Field | Type | Description |
|---|---|---|
| `value` | `float` | Scalar reward strictly clamped in the range `[0.01, 0.99]` |

---

## Tasks and Difficulty

### Task 1 — Easy: Supply Chain Secret Leak (CWE-798)

**Objective:** Remove a hardcoded legacy PyPI API token from a deployment module and replace it with a secure `os.getenv()` or `os.environ.get()` call.
*Derived from open-source patterns where configurations mistakenly ship with hardcoded fallback API keys (e.g., Flask-AppBuilder CVE-2023-30861, Apache Airflow).*

**Grading Breakdown:**
| Condition | Reward |
|---|---|
| Hardcoded secret string is accurately stripped from the patched code | +0.5 |
| Code uses a safe env-var access pattern (AST-verified) | +0.5 |

---

### Task 2 — Medium: Insecure YAML Deserialization (CWE-502)

**Objective:** Replace an unsafe `yaml.load()` call in a project configuration parser (`project.yaml`) with `yaml.safe_load()` to prevent arbitrary code execution during build tasks.
*Sourced directly from the fallout of the PyYAML code execution flaws (CVE-2017-18342 / CVE-2020-14343) which compromised vast swathes of Python developer infrastructure.*

**Grading Breakdown:**
| Condition | Reward |
|---|---|
| Vulnerable `yaml.load` call is entirely absent from the patched code | +0.3 |
| Agent utilizes `yaml.safe_load` exclusively (AST-verified) | +0.7 |

---

### Task 3 — Hard: CI/CD Command Injection (CWE-78)

**Objective:** Refactor a `setup.py` build-validation step that passes unsanitized repository URLs to `os.system()`. The agent must rewrite this into an isolated, list-based `subprocess.run()` execution flow.
*Sourced closely from the style of command injections found in utility packages like youtube-dl (CVE-2020-15366) and CI scripts.*

**Grading Breakdown:**
| Condition | Reward |
|---|---|
| `os.system` is removed from the patched code | +0.3 |
| `subprocess.run()` (or equivalent) is called with a list argument and `shell=False` (AST-verified) | +0.7 |

---

## Reward Function Design

The reward function is designed to provide **meaningful signal over the full trajectory**, not just at episode end.

| Event | Reward | Rationale |
|---|---|---|
| `run_scan` action | +0.1 | Encourages information gathering before patching |
| Correct patch (full credit) | ~0.99 | Agent removed the vulnerability and used the correct AST pattern |
| Partial patch (fallback) | +0.4 to +0.7 | Agent improved security but did not use the ideal pattern |
| Reaching step 5 without completing | -0.2 | Penalizes agents that loop endlessly |
| All rewards | Clamped to `[0.01, 0.99]` | Strict compliance with latest OpenEnv spec rules |

---

## Grading Methodology (Abstract Syntax Trees)

A key design decision in this environment is the use of **Python's Abstract Syntax Tree (AST) module** for grading, rather than brittle Regex string matching. This guarantees the grading is resistant to false negatives from an LLM reformatting the whitespaces, comment placements, or import styles. 

Each grader function (`uses_os_getenv`, `uses_safe_yaml`, `uses_safe_subprocess`) parses the submitted code into an execution tree, walking the nodes to verify that actual secure API routes were wired up at a structural level.

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

**4. Use the environment natively:**
```python
from environment import VulnPatchEnv, Action

# Run the difficult Task
env = VulnPatchEnv(task="hard")
obs = env.reset()
print(obs.current_code)

# Run an SCA Scan
obs, reward, done, info = env.step(Action(action_type="run_scan"))
print(obs.linter_output)
```

## Baseline Inference Evaluation

The included `inference.py` evaluates all 3 tasks automatically against an OpenAI-compatible endpoint.

```bash
export HF_TOKEN="your_hf_token_here"
export MODEL_NAME="meta-llama/Llama-3.3-70B-Instruct"
export API_BASE_URL="https://router.huggingface.co/v1"

python inference.py
```
