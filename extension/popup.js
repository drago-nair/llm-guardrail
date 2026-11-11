const API_URL = "http://192.168.0.111:8000/check";

const promptInput = document.getElementById("prompt-input");
const apiKeyInput = document.getElementById("api-key-input");
const checkButton = document.getElementById("check-button");
const resultBox = document.getElementById("result");
const verdictBadge = document.getElementById("verdict-badge");
const rejectionReason = document.getElementById("rejection-reason");
const outputText = document.getElementById("output-text");
const copyButton = document.getElementById("copy-button");
const errorMessage = document.getElementById("error-message");
const authErrorMessage = document.getElementById("auth-error-message");

chrome.storage.local.get(["apiKey"], (stored) => {
  if (stored.apiKey) {
    apiKeyInput.value = stored.apiKey;
  }
});

apiKeyInput.addEventListener("change", () => {
  chrome.storage.local.set({ apiKey: apiKeyInput.value });
});

function setVerdict(label, cssClass) {
  verdictBadge.textContent = label;
  verdictBadge.className = cssClass;
}

checkButton.addEventListener("click", async () => {
  const prompt = promptInput.value.trim();
  if (!prompt) {
    return;
  }

  resultBox.classList.add("hidden");
  errorMessage.classList.add("hidden");
  authErrorMessage.classList.add("hidden");
  checkButton.disabled = true;
  checkButton.textContent = "Checking...";

  try {
    const response = await fetch(API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": apiKeyInput.value,
      },
      body: JSON.stringify({ prompt }),
    });

    if (response.status === 401) {
      authErrorMessage.classList.remove("hidden");
      return;
    }

    const body = await response.json();
    const wasReviewFlagged = body.audit_flags.some((flag) =>
      flag.includes("REVIEW")
    );

    if (!body.is_allowed) {
      setVerdict("BLOCKED", "verdict-block");
      rejectionReason.textContent = body.rejection_reason;
      rejectionReason.classList.remove("hidden");
    } else if (wasReviewFlagged) {
      setVerdict("REVIEW", "verdict-review");
      rejectionReason.classList.add("hidden");
    } else {
      setVerdict("ALLOWED", "verdict-allow");
      rejectionReason.classList.add("hidden");
    }

    outputText.value = body.processed_prompt;
    resultBox.classList.remove("hidden");
  } catch (error) {
    errorMessage.classList.remove("hidden");
  } finally {
    checkButton.disabled = false;
    checkButton.textContent = "Check";
  }
});

copyButton.addEventListener("click", () => {
  navigator.clipboard.writeText(outputText.value);
  copyButton.textContent = "Copied!";
  setTimeout(() => {
    copyButton.textContent = "Copy cleaned prompt";
  }, 1200);
});
