import json
import os

from dotenv import load_dotenv

load_dotenv()
from openai import OpenAI

from environment import Action, VulnPatchEnv

# Strict Environment Variables required by the hackathon rubric
API_BASE_URL = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
MODEL_NAME = os.getenv("MODEL_NAME", "meta-llama/Llama-3.3-70B-Instruct")
HF_TOKEN = os.getenv("HF_TOKEN")

if not HF_TOKEN:
    print("WARNING: HF_TOKEN is missing. API calls will fail.", flush=True)

client = OpenAI(base_url=API_BASE_URL, api_key=HF_TOKEN)


def run_episode(task_name: str):
    env = VulnPatchEnv(task=task_name)
    obs = env.reset()

    # REQUIRED [START] line
    print(f"[START] task={task_name} env=vuln-patch-env model={MODEL_NAME}", flush=True)

    done = False
    rewards = []

    try:
        while not done:
            prompt = (
                f"Task: Fix the vulnerability in the code.\n"
                f"Observation: {obs.model_dump_json()}\n"
                "Output valid JSON ONLY. Required keys:\n"
                "- 'action_type': Must be 'run_scan' or 'submit_patch'.\n"
                "- 'patched_code': The patched python code (string). Only required if submitting."
            )

            try:
                response = client.chat.completions.create(
                    model=MODEL_NAME,
                    messages=[
                        {
                            "role": "system",
                            "content": "You are a cyber security agent who is an expert in python and security. You are given a task to fix the vulnerability in the code and can find bugs in the code also. Always output valid JSON.",
                        },
                        {"role": "user", "content": prompt},
                    ],
                    response_format={"type": "json_object"},
                    temperature=0.0,  # Deterministic LLM response
                    timeout=60,  # Prevent indefinite hang on slow API
                )
                raw_content = response.choices[0].message.content
                action_data = json.loads(raw_content)
                action = Action(**action_data)
                error_msg = "null"
            except Exception as e:
                action = Action(action_type="error", patched_code="")
                error_msg = str(e).replace("\n", " ")

            # Step the environment
            obs, reward_obj, done, info = env.step(action)
            reward = reward_obj.value
            rewards.append(reward)

            # Use environment's info.error if set, else fall back to LLM error, else null
            env_error = info.error if info.error else None
            step_error = env_error or (error_msg if error_msg != "null" else None)
            step_error_str = step_error if step_error else "null"

            # REQUIRED [STEP] line (no newlines, 2 decimal places, lowercase bools)
            action_safe_str = f"{action.action_type}()"
            done_str = "true" if done else "false"
            print(
                f"[STEP] step={env.step_count} action={action_safe_str} reward={reward:.2f} done={done_str} error={step_error_str}",
                flush=True,
            )

    finally:
        env.close()
        # REQUIRED [END] line — always emitted even on exception, score to 2 decimal places
        score = rewards[-1] if rewards else 0.01
        score = min(
            max(score, 0.01), 0.99
        )  # Strictly within (0, 1) — exclusive of 0 and 1

        success_str = "true" if score >= 0.8 else "false"
        rewards_str = ",".join([f"{r:.2f}" for r in rewards])
        print(
            f"[END] success={success_str} steps={env.step_count} score={score:.2f} rewards={rewards_str}",
            flush=True,
        )


if __name__ == "__main__":
    for t in ["easy", "medium", "hard"]:
        run_episode(t)
