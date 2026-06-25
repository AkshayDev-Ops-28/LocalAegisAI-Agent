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
6. CRITICAL — use ONLY these standalone resource types to remediate, never inline blocks:
   - CKV_AWS_21  (versioning)  → aws_s3_bucket_versioning
   - CKV_AWS_18  (logging)     → aws_s3_bucket_logging
   - CKV2_AWS_6  (public access block) → aws_s3_bucket_public_access_block
   - CKV2_AWS_61 (lifecycle)   → aws_s3_bucket_lifecycle_configuration
   - CKV2_AWS_62 (notifications) → aws_s3_bucket_notification
7. For aws_s3_bucket_versioning use this exact structure:
   resource "aws_s3_bucket_versioning" "aegis_data" {{
     bucket = aws_s3_bucket.aegis_data.id
     versioning_configuration {{
       status = "Enabled"
     }}
   }}
8. For aws_s3_bucket_logging the target_bucket must be a separate aws_s3_bucket resource.
9. The aws_s3_bucket_notification must reference a valid aws_sns_topic resource.
10.  CRITICAL — Every single rule block inside EVERY aws_s3_bucket_lifecycle_configuration resource MUST contain this exact block with no exceptions:
    abort_incomplete_multipart_upload {{
      days_after_initiation = 7
    }}
    A complete correct rule block looks exactly like this:
    rule {{
      id     = "main"
      status = "Enabled"
      filter {{
        prefix = ""
      }}
      expiration {{
        days = 90
      }}
      abort_incomplete_multipart_upload {{
        days_after_initiation = 7
      }}
    }}
    Apply this structure to EVERY rule block in EVERY aws_s3_bucket_lifecycle_configuration resource in the file.
11. Any aws_sns_topic resource MUST include encryption:
    resource "aws_sns_topic" "aegis_data" {{
      name              = "localaegis-data-topic"
      kms_master_key_id = "alias/aws/sns"
    }}
12. The logging bucket aws_s3_bucket.aegis_logging MUST also have its own aws_s3_bucket_notification resource:
    resource "aws_s3_bucket_notification" "aegis_logging" {{
      bucket = aws_s3_bucket.aegis_logging.id
      topic {{
        topic_arn = aws_sns_topic.aegis_data.arn
        events    = ["s3:ObjectCreated:*"]
      }}
    }}

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
    print("\n[DEBUG] LLM OUTPUT:\n")
    print(fixed_code)
    print("\n[END DEBUG]\n")