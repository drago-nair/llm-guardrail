# ==========================================
# Project: LLM Guardrail Security Engine
# Milestone 3: Initial Engine Test
# ==========================================

ENGINE_NAME = "SentinelGuard"
VERSION = "0.1.0"
STATUS = "OPERATIONAL"

sample_user_prompt = "Hello! Explain what an LLM guardrail does."

print("=" * 45)
print(f"[*] {ENGINE_NAME} v{VERSION}")
print(f"[*] Engine Status : {STATUS}")
print("-" * 45)
print(f"[*] Raw Prompt    : \"{sample_user_prompt}\"")
print(f"[*] Prompt Length : {len(sample_user_prompt)} characters")
print("=" * 45)