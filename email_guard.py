"""
email_guard.py
A simple phishing/suspicious-email triage tool.
Author: Juan (GHOSTx33) - 2026
"""

SUSPICIOUS_KEYWORDS = [
    "verify your account", "urgent action required", "wire transfer",
    "click here immediately", "suspended", "confirm your password",
    "gift card", "bitcoin", "irs", "social security number"
]

def check_email(sender, subject, body):
    """Returns a risk score and reasons for a given email."""
    score = 0
    reasons = []

    text = (subject + " " + body).lower()

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in text:
            score += 1
            reasons.append(f"Contains suspicious phrase: '{keyword}'")

    if "@" not in sender or sender.count("@") > 1:
        score += 2
        reasons.append("Sender address looks malformed")

    if score >= 3:
        verdict = "HIGH RISK"
    elif score >= 1:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LIKELY SAFE"

    return {
        "sender": sender,
        "subject": subject,
        "score": score,
        "verdict": verdict,
        "reasons": reasons
    }


# --- Test it with a few sample emails ---
if __name__ == "__main__":
    test_emails = [
        {
            "sender": "security@paypal-verify.com",
            "subject": "URGENT: Verify your account now",
            "body": "Click here immediately or your account will be suspended."
        },
        {
            "sender": "mom@gmail.com",
            "subject": "Dinner Sunday?",
            "body": "Hey hon, you coming over this weekend?"
        }
    ]

    for email in test_emails:
        result = check_email(email["sender"], email["subject"], email["body"])
        print(result)
