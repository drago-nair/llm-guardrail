import sys
from pathlib import Path

# Add src to Python path so sentinel_guard is importable
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from sentinel_guard import run_deterministic_pipeline

if __name__ == "__main__":
    prompt = "Contact security at sec@corp.com with ghp_111122223333444455556666777788889999."
    result = run_deterministic_pipeline(prompt)
    
    print("=" * 60)
    print(f"Verdict     : {'ALLOWED' if result.is_allowed else 'BLOCKED'}")
    print(f"Safe Prompt : {result.processed_prompt}")
    print(f"Vault       : {result.anonymization_vault}")
    print(f"Audit Flags : {result.audit_flags}")
    print("=" * 60)