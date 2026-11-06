from dataclasses import dataclass

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

DEFAULT_MODEL_NAME = "meta-llama/Llama-Prompt-Guard-2-22M"

DEFAULT_MODEL_REVISION = (
    "11614a155199674a0a95e6602d6ab0417b790ed0"
)

MAX_INPUT_TOKENS = 512

# The model's own config.id2label only reports generic names
# ("LABEL_0", "LABEL_1"), not BENIGN/MALICIOUS. This mapping was
# determined empirically in Milestone 21 by scanning known-benign
# and known-attack prompts and observing which index scored high
# on which. It is re-verified at startup rather than trusted
# blindly, because a model update could silently change it.
EXPECTED_ID2LABEL = {0: "LABEL_0", 1: "LABEL_1"}
BENIGN_LABEL_INDEX = 0
MALICIOUS_LABEL_INDEX = 1


@dataclass
class ClassifierScanResult:
    """Structured, uncalibrated evidence returned by the Classifier Shield."""

    model_label: str
    benign_score: float
    malicious_score: float
    confidence: float
    model_name: str
    model_revision: str | None


class ClassifierShield:
    """
    Scores a prompt with a trained binary prompt-attack classifier.

    This class returns raw, uncalibrated evidence only. Converting a
    score into an ALLOW/BLOCK decision is a separate, later policy
    step, not this module's job.
    """

    def __init__(
        self,
        model_name: str = DEFAULT_MODEL_NAME,
        model_revision: str | None = DEFAULT_MODEL_REVISION,
        max_input_tokens: int = MAX_INPUT_TOKENS,
    ):
        if max_input_tokens < 1:
            raise ValueError("max_input_tokens must be at least 1")

        self.model_name = model_name
        self.model_revision = model_revision
        self.max_input_tokens = max_input_tokens

        self.tokenizer = AutoTokenizer.from_pretrained(
            model_name,
            revision=model_revision,
        )

        self.model = AutoModelForSequenceClassification.from_pretrained(
            model_name,
            revision=model_revision,
            use_safetensors=True,
        )

        self.model.to("cpu")
        self.model.eval()

        self._verify_label_mapping()

    def _verify_label_mapping(self) -> None:
        """
        Fails loudly if the model's label mapping no longer matches
        the Milestone 21 empirical baseline, instead of silently
        trusting a numeric class order that may have changed.
        """
        actual_mapping = dict(self.model.config.id2label)

        if actual_mapping != EXPECTED_ID2LABEL:
            raise ValueError(
                "Classifier label mapping changed from the verified "
                f"baseline. Expected {EXPECTED_ID2LABEL}, got "
                f"{actual_mapping}. Re-verify BENIGN_LABEL_INDEX and "
                "MALICIOUS_LABEL_INDEX against known-safe and "
                "known-attack prompts before trusting this model."
            )

    def scan(self, prompt: str) -> ClassifierScanResult:
        """Scores one prompt and returns raw, uncalibrated evidence."""
        encoded_prompt = self.tokenizer(
            prompt,
            return_tensors="pt",
            truncation=True,
            max_length=self.max_input_tokens,
        )

        with torch.inference_mode():
            logits = self.model(**encoded_prompt).logits
            probabilities = torch.softmax(logits, dim=-1)[0]

        predicted_index = int(torch.argmax(probabilities).item())

        return ClassifierScanResult(
            model_label=self.model.config.id2label[predicted_index],
            benign_score=float(probabilities[BENIGN_LABEL_INDEX]),
            malicious_score=float(probabilities[MALICIOUS_LABEL_INDEX]),
            confidence=float(probabilities[predicted_index]),
            model_name=self.model_name,
            model_revision=self.model_revision,
        )
