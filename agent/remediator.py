import os
import re
from groq import Groq
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

TF_PATH = os.path.join(os.path.dirname(__file__), "..", "terraform", "main.tf")

def load_tf_source(tf_path: str = TF_PATH) -> str:
    with open(tf_path, "r", encoding="utf-8") as f:
        return f.read()


def build_prompt(violations: list[dict], tf_source: str) -> str:
    violation_block = ""
    for v in violations:
        violation_block += (
            f"- [{v['check_id']}] {v['check_name']}\n"
            f"  Resource: {v['resource']}\n"
            f"  Guideline: {v['guideline']}\n\n"
        )

    prompt = f"""You are a senior AWS security engineer and Terraform expert.

The following Terraform file has been scanned by Checkov and contains security violations.
Your job is to rewrite the ENTIRE file with ALL violations remediated.

VIOLATIONS TO FIX:
{violation_block}

ORIGINAL TERRAFORM CODE:
```hcl
{tf_source}
```

STRICT RULES:
1. Return ONLY valid Terraform HCL code — no explanations, no markdown, no comments outside the code.
2. Fix every single violation listed above.
3. Do not remove or rename any existing resources.
4. Do not add placeholder values — use real, valid Terraform syntax.
5. Wrap your response in ```hcl ... ``` code fences and nothing else.

Respond with the complete remediated Terraform file now.
"""
    return prompt


def extract_hcl(raw_response: str) -> str:
    match = re.search(r"```hcl\s*(.*?)```", raw_response, re.DOTALL)
    if match:
        return match.group(1).strip()
    return raw_response.strip()


def remediate(violations: list[dict]) -> str:
    client = Groq(api_key=os.getenv("GROQ_API_KEY"))
    tf_source = load_tf_source()
    prompt = build_prompt(violations, tf_source)

    print("[remediator] Sending prompt to Groq (llama-3.3-70b-versatile)...")

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2,
    )

    raw = response.choices[0].message.content
    fixed_tf = extract_hcl(raw)

    print("[remediator] Response received. Extracting HCL...")
    return fixed_tf


if __name__ == "__main__":
    from scanner import load_violations
    violations = load_violations()
    fixed_code = remediate(violations)
    print("\n[remediator] Remediated Terraform:\n")
    print(fixed_code)