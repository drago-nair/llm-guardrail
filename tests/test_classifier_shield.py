import types

import pytest
import torch

import sentinel_guard.classifier_shield as classifier_shield_module
from sentinel_guard.classifier_shield import (
    ClassifierScanResult,
    ClassifierShield,
    EXPECTED_ID2LABEL,
)


class FakeTokenizer:
    """Stunt double for AutoTokenizer -- ignores its input, returns a fixed encoding."""

    def __call__(self, prompt, return_tensors=None, truncation=None, max_length=None):
        return {"input_ids": torch.tensor([[1, 2, 3]])}


class FakeModel:
    """Stunt double for AutoModelForSequenceClassification with fully controlled output."""

    def __init__(self, id2label, logits):
        self.config = types.SimpleNamespace(id2label=id2label)
        self._logits = logits

    def to(self, device):
        return self

    def eval(self):
        return self

    def __call__(self, **kwargs):
        return types.SimpleNamespace(logits=self._logits)


def _install_fake_backend(monkeypatch, id2label, logits):
    """Replaces real HF model/tokenizer loading with controllable fakes."""
    monkeypatch.setattr(
        classifier_shield_module.AutoTokenizer,
        "from_pretrained",
        lambda *args, **kwargs: FakeTokenizer(),
    )
    monkeypatch.setattr(
        classifier_shield_module.AutoModelForSequenceClassification,
        "from_pretrained",
        lambda *args, **kwargs: FakeModel(id2label, logits),
    )


def test_matching_label_mapping_loads_successfully(monkeypatch):
    """A model whose id2label matches the verified baseline loads without error."""
    _install_fake_backend(
        monkeypatch,
        id2label=dict(EXPECTED_ID2LABEL),
        logits=torch.tensor([[5.0, 1.0]]),
    )

    shield = ClassifierShield()

    assert shield.model.config.id2label == EXPECTED_ID2LABEL


def test_mismatched_label_mapping_raises(monkeypatch):
    """
    A model whose id2label no longer matches the Milestone 21 baseline
    must fail loudly instead of silently trusting a changed class order.
    This is the one failure path the real model can never exercise.
    """
    _install_fake_backend(
        monkeypatch,
        id2label={0: "BENIGN", 1: "MALICIOUS"},
        logits=torch.tensor([[5.0, 1.0]]),
    )

    with pytest.raises(ValueError, match="label mapping changed"):
        ClassifierShield()


def test_scan_reports_benign_label_and_scores(monkeypatch):
    """Verifies scan() converts dominant benign logits into the right label/scores."""
    _install_fake_backend(
        monkeypatch,
        id2label=dict(EXPECTED_ID2LABEL),
        logits=torch.tensor([[5.0, 1.0]]),
    )
    shield = ClassifierShield()

    result = shield.scan("irrelevant text -- the fake model ignores it")

    assert isinstance(result, ClassifierScanResult)
    assert result.model_label == "LABEL_0"
    assert result.benign_score > result.malicious_score
    assert result.confidence == result.benign_score
    assert abs(result.benign_score + result.malicious_score - 1.0) < 1e-6


def test_scan_reports_malicious_label_and_scores(monkeypatch):
    """Verifies scan() converts dominant malicious logits into the right label/scores."""
    _install_fake_backend(
        monkeypatch,
        id2label=dict(EXPECTED_ID2LABEL),
        logits=torch.tensor([[0.1, 6.0]]),
    )
    shield = ClassifierShield()

    result = shield.scan("irrelevant text -- the fake model ignores it")

    assert result.model_label == "LABEL_1"
    assert result.malicious_score > result.benign_score
    assert result.confidence == result.malicious_score


def test_scan_includes_model_metadata(monkeypatch):
    """Verifies scan() echoes back the model name/revision it was constructed with."""
    _install_fake_backend(
        monkeypatch,
        id2label=dict(EXPECTED_ID2LABEL),
        logits=torch.tensor([[3.0, 0.5]]),
    )
    shield = ClassifierShield(
        model_name="fake/model",
        model_revision="deadbeef",
    )

    result = shield.scan("hello")

    assert result.model_name == "fake/model"
    assert result.model_revision == "deadbeef"


def test_invalid_max_input_tokens_raises():
    """
    Verifies max_input_tokens is validated before any model/tokenizer
    loading is attempted -- no fake backend needed, since this should
    fail before reaching that code at all.
    """
    with pytest.raises(ValueError):
        ClassifierShield(max_input_tokens=0)
