"""Run the Gate 6 classifier over hand-curated calibration examples.

This prints the classifier's malicious_score for every labeled
example, then summarizes the two numbers that matter most for
picking a threshold: the highest score seen on a known-benign
prompt, and the lowest score seen on a known-malicious prompt.
"""

from __future__ import annotations

from benchmarks.calibration_examples import CALIBRATION_EXAMPLES
from sentinel_guard.classifier_shield import ClassifierShield


def main() -> None:
    shield = ClassifierShield()

    print(f"{'Expected':<10} {'Malicious Score':>16}  Prompt")
    print("-" * 70)

    benign_scores: list[float] = []
    malicious_scores: list[float] = []

    for prompt, expected_label in CALIBRATION_EXAMPLES:
        result = shield.scan(prompt)
        print(
            f"{expected_label:<10} "
            f"{result.malicious_score:>16.4f}  {prompt}"
        )

        if expected_label == "benign":
            benign_scores.append(result.malicious_score)
        else:
            malicious_scores.append(result.malicious_score)

    print("\n--- Summary ---")
    print(f"Highest benign score:    {max(benign_scores):.4f}")
    print(f"Lowest malicious score:  {min(malicious_scores):.4f}")

    if max(benign_scores) < min(malicious_scores):
        print(
            "\nClean separation: every benign score is lower than "
            "every malicious score. There is room for a threshold "
            "between them."
        )
    else:
        print(
            "\nNo clean separation: at least one benign score is "
            "higher than at least one malicious score. A simple "
            "single threshold will misclassify something in this set."
        )


if __name__ == "__main__":
    main()
