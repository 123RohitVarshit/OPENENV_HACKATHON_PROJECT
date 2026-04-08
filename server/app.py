"""
server/app.py — OpenEnv-compatible FastAPI application.
This is the canonical app entry point expected by `openenv validate`.
The root server.py re-exports this for backwards compatibility.
"""
from fastapi import FastAPI, Request
from environment import VulnPatchEnv

app = FastAPI(
    title="vuln-patch-env",
    description="OpenEnv environment for code vulnerability detection and patching.",
    version="1.0.0",
)

# One shared environment instance per server process (stateless reset on each call)
_env = VulnPatchEnv()


@app.get("/")
async def health_check():
    return {"status": "running", "message": "vuln-patch-env OpenEnv Server is live"}


@app.get("/health")
async def health():
    """Required by openenv validate — must return {"status": "healthy"}."""
    return {"status": "healthy"}


@app.get("/metadata")
async def metadata():
    """Required by openenv validate — must return name and description."""
    return {
        "name": "vuln-patch-env",
        "description": (
            "A real-world code security environment where AI agents detect "
            "and patch vulnerabilities (hardcoded secrets, SQL injection, "
            "command injection) in Python code."
        ),
        "version": "1.0.0",
        "tasks": ["easy", "medium", "hard"],
    }


@app.get("/schema")
async def schema():
    """Required by openenv validate — must return action, observation and state schemas."""
    from environment import Action, Observation
    return {
        "action": Action.model_json_schema(),
        "observation": Observation.model_json_schema(),
        "state": Observation.model_json_schema(),  # state has same shape as observation
    }


@app.post("/mcp")
async def mcp_endpoint(request: Request):
    """
    Minimal Model Context Protocol (MCP) endpoint.
    Required by openenv validate — must return a JSON-RPC 2.0 envelope.
    """
    try:
        body = await request.json()
    except Exception:
        body = {}

    return {
        "jsonrpc": "2.0",
        "id": body.get("id", 1),
        "result": {
            "name": "vuln-patch-env",
            "description": "OpenEnv environment for code vulnerability patching.",
            "tools": ["reset", "step", "state"],
        },
    }


@app.post("/reset")
async def reset_endpoint(request: Request):
    """Reset the environment and return the initial observation."""
    try:
        body = await request.json()
        task = body.get("task", "easy")
    except Exception:
        task = "easy"

    _env.task = task
    obs = _env.reset()
    return {"status": "ok", "observation": obs.model_dump()}


@app.post("/step")
async def step_endpoint(request: Request):
    """Take one step in the environment."""
    from environment import Action
    try:
        body = await request.json()
        action = Action(**body)
    except Exception as e:
        return {"error": str(e)}, 400

    obs, reward, done, info = _env.step(action)
    return {
        "observation": obs.model_dump(),
        "reward": reward.value,
        "done": done,
        "info": info.model_dump(),
    }


@app.get("/state")
async def state_endpoint():
    """Return the current environment state."""
    return {"observation": _env.state().model_dump()}


def main():
    """Entry point for the server script (used by pyproject.toml [project.scripts])."""
    import uvicorn
    uvicorn.run("server.app:app", host="0.0.0.0", port=7860, reload=False)


if __name__ == "__main__":
    main()
