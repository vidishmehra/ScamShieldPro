from flask import Flask, request, render_template
import joblib

app = Flask(__name__)

# Load the trained ScamShield AI
model = joblib.load("app/models/scamshield_ai_v5_word.pkl")
vectorizer = None


def analyze_message(message):
    import re

    # Load the V5 ML pipeline
    v5_word_model = joblib.load("app/models/scamshield_ai_v5_word.pkl")

    message_lower = message.lower()

    # --------------------------------------------------
    # V5 SECURITY INTELLIGENCE
    # --------------------------------------------------

    patterns = {
        "OTP": [r"\botp\b", r"one time password", r"verification code"],
        "Password": [r"\bpassword\b", r"passcode"],
        "Card Credentials": [
            r"\bcvv\b", r"\bpin\b", r"card number",
            r"debit card", r"credit card"
        ],
        "Banking": [
            r"\bbank\b", r"bank account", r"net banking",
            r"upi", r"wallet"
        ],
        "Account Threat": [
            r"account.*(blocked|suspended|closed|compromised)",
            r"(blocked|suspended|compromised).*account",
            r"account will be"
        ],
        "Verification": [
            r"\bverify\b", r"verification", r"confirm your",
            r"verify your identity"
        ],
        "Login": [
            r"\blogin\b", r"sign in", r"log in"
        ],
        "Account Security Alert": [
            r"new device",
            r"recent sign[- ]?in attempt",
            r"sign[- ]?in attempt",
            r"if this was not you",
            r"review your account activity",
            r"keep your account secure"
        ],
        "Suspicious Link": [
            r"click here", r"\bclick\b.*\blink\b",
            r"open the link", r"follow this link",
            r"https?://", r"www\."
        ],
        "Payment": [
            r"\bpay\b", r"\bpayment\b", r"send money",
            r"transfer", r"processing fee", r"pay ₹",
            r"pay rs", r"deposit"
        ],
        "Refund": [
            r"\brefund\b", r"cashback", r"money back",
            r"refund.*otp", r"refund.*card"
        ],
        "KYC": [
            r"\bkyc\b", r"pan card", r"pan\b",
            r"kyc.*expired", r"kyc.*failed"
        ],
        "Urgency": [
            r"\burgent\b", r"\bimmediately\b", r"act now",
            r"right now", r"last chance", r"within \d+ hours",
            r"expires? today", r"today.*deadline"
        ],
        "Prize": [
            r"\bprize\b", r"\bwinner\b", r"\bwon\b",
            r"lottery", r"cash reward", r"reward",
            r"bonus", r"congratulations", r"₹[\d,]+"
        ],
        "Delivery": [
            r"package", r"parcel", r"delivery",
            r"shipped", r"delivered", r"courier"
        ]
    }

    weights = {
        "OTP": 35,
        "Password": 35,
        "Card Credentials": 40,
        "Banking": 15,
        "Account Threat": 30,
        "Verification": 15,
        "Login": 15,
        "Account Security Alert": 30,
        "Suspicious Link": 20,
        "Payment": 25,
        "Refund": 15,
        "KYC": 25,
        "Urgency": 15,
        "Prize": 25,
        "Delivery": -15
    }

    detected = {}
    security_score = 0

    for category, regexes in patterns.items():
        matches = []
        for pattern in regexes:
            if re.search(pattern, message_lower):
                matches.append(pattern)

        if matches:
            detected[category] = matches
            security_score += weights.get(category, 0)

    # Keep security score within bounds.
    security_score = max(0, min(100, security_score))

    # --------------------------------------------------
    # MACHINE LEARNING SCORE
    # --------------------------------------------------

    try:
        probabilities = v5_word_model.predict_proba([message])[0]
        classes = list(v5_word_model.classes_)

        if "scam" in classes:
            scam_index = classes.index("scam")
            ml_score = float(probabilities[scam_index]) * 100
        else:
            prediction = v5_word_model.predict([message])[0]
            ml_score = 100.0 if prediction == "scam" else 0.0

        prediction = v5_word_model.predict([message])[0]

    except Exception:
        prediction = v5_word_model.predict([message])[0]
        ml_score = 100.0 if prediction == "scam" else 0.0

    # --------------------------------------------------
    # HYBRID V5 RISK ENGINE
    # --------------------------------------------------

    risk_score = (0.55 * ml_score) + (0.45 * security_score)

    # High-confidence security overrides
    if "OTP" in detected and "Banking" in detected:
        risk_score = max(risk_score, 85)

    if "OTP" in detected and "Refund" in detected:
        risk_score = max(risk_score, 88)

    if "Card Credentials" in detected and (
        "Payment" in detected or "Refund" in detected
    ):
        risk_score = max(risk_score, 92)

    if "Password" in detected and (
        "Payment" in detected or "Refund" in detected
    ):
        risk_score = max(risk_score, 90)

    if (
        "Suspicious Link" in detected
        and "Login" in detected
        and "Verification" in detected
    ):
        risk_score = max(risk_score, 85)

    if "KYC" in detected and "Payment" in detected:
        risk_score = max(risk_score, 85)

    if "Prize" in detected and "Payment" in detected:
        risk_score = max(risk_score, 90)

    if (
        "Account Security Alert" in detected
        and "Login" in detected
        and "Verification" in detected
    ):
        risk_score = max(risk_score, 90)

    if (
        "Account Security Alert" in detected
        and "Verification" in detected
    ):
        risk_score = max(risk_score, 82)

    # --------------------------------------------------
    # LEGITIMATE FINANCIAL CONTEXT
    # Prevent normal completed/credited notifications
    # from being treated as scams.
    # --------------------------------------------------

    benign_financial_patterns = [
        r"salary .* credited",
        r"salary .* received",
        r"payment .* received",
        r"payment .* successful",
        r"payment .* processed",
        r"transaction .* completed",
        r"transaction .* successful",
        r"statement .* available",
        r"credited to .* account"
    ]

    benign_financial_matches = sum(
        1 for pattern in benign_financial_patterns
        if re.search(pattern, message_lower)
    )

    strong_scam_indicators = {
        "OTP",
        "Password",
        "Card Credentials",
        "Suspicious Link",
        "Prize",
        "KYC",
        "Refund"
    }

    if (
        benign_financial_matches >= 1
        and not any(item in detected for item in strong_scam_indicators)
        and "Urgency" not in detected
        and "Account Threat" not in detected
        and "Payment" not in detected
    ):
        risk_score = min(risk_score, 35)
        detected.pop("Banking", None)


    # BENIGN FINANCIAL CONTEXT
    benign_financial_patterns = [
        r"\bsalary has been credited\b",
        r"\bsalary credited\b",
        r"\bsalary has been deposited\b",
        r"\bsalary credited to\b",
        r"\bincome has been credited\b",
        r"\bpayment received\b",
        r"\bamount has been credited\b",
        r"\bdeposit has been made\b"
    ]

    strong_scam_indicators = [
        "otp", "one time password", "cvv", "pin",
        "password", "click here", "verify your identity",
        "processing fee", "pay immediately", "send money",
        "transfer money", "claim your reward"
    ]

    benign_financial_context = any(
        re.search(pattern, message_lower)
        for pattern in benign_financial_patterns
    )

    strong_scam_context = any(
        indicator in message_lower
        for indicator in strong_scam_indicators
    )

    if benign_financial_context and not strong_scam_context:
        risk_score = min(risk_score, 30)
        detected.pop("Banking", None)


    # BENIGN BANKING / SERVICE-NOTICE CONTEXT
    benign_banking_patterns = [
        r"\broutine maintenance\b",
        r"\bscheduled maintenance\b",
        r"\bmaintenance for online banking\b",
        r"\bfeatures may be temporarily unavailable\b",
        r"\bservices may be temporarily unavailable\b",
        r"\bno action is required\b",
        r"\bno action needed\b"
    ]

    benign_banking_context = any(
        re.search(pattern, message_lower)
        for pattern in benign_banking_patterns
    )

    if benign_banking_context and not strong_scam_context:
        risk_score = min(risk_score, 30)
        detected.pop("Banking", None)


    # LEGITIMATE PAYMENT / CREDIT / TRANSFER CONTEXT
    benign_transaction_patterns = [
        r"\bpayment .*successfully processed\b",
        r"\bpayment was successful\b",
        r"\bpayment has been successful\b",
        r"\btransaction was successful\b",
        r"\btransaction has been completed\b",
        r"\bmoney has been credited\b",
        r"\bamount has been credited\b",
        r"\bfriend sent you\b",
        r"\bhas been credited to your account\b",
        r"\bcredited to your account\b"
    ]

    # Strong account-threat language should outweigh generic banking terms.
    strong_account_threat_patterns = [
        r"\baccount .*blocked\b",
        r"\baccount .*suspended\b",
        r"\baccount .*will be blocked\b",
        r"\baccount .*will be suspended\b",
        r"\bunless you verify\b",
        r"\bverify your identity\b.*\blink\b",
        r"\bclick .*link\b.*\bverify\b"
    ]

    benign_transaction_context = any(
        re.search(pattern, message_lower)
        for pattern in benign_transaction_patterns
    )

    strong_account_threat = any(
        re.search(pattern, message_lower)
        for pattern in strong_account_threat_patterns
    )

    if benign_transaction_context and not strong_scam_context:
        risk_score = min(risk_score, 30)
        detected.pop("Banking", None)
        detected.pop("Payment", None)

    if strong_account_threat:
        risk_score = max(risk_score, 75)

    risk_score = round(min(100, max(0, risk_score)))

    # --------------------------------------------------
    # LEGITIMATE SECURITY CONTEXT
    # Reduce false positives for genuine security notices.
    # --------------------------------------------------

    benign_security_patterns = [
        r"no action is needed",
        r"no action required",
        r"successfully registered",
        r"official app",
        r"official website",
        r"if you recognize this device",
        r"review .* from the official app"
    ]

    benign_security_matches = sum(
        1 for pattern in benign_security_patterns
        if re.search(pattern, message_lower)
    )

    if (
        "Account Security Alert" in detected
        and benign_security_matches >= 2
        and "OTP" not in detected
        and "Payment" not in detected
        and "Password" not in detected
        and "Card Credentials" not in detected
        and "Suspicious Link" not in detected
    ):
        risk_score = min(risk_score, 35)

    # --------------------------------------------------
    # LEGITIMATE FINANCIAL CONTEXT
    # Reduce false positives for normal financial notifications.
    # --------------------------------------------------

    benign_financial_patterns = [
        r"salary .* credited",
        r"payment .* received",
        r"payment .* successful",
        r"payment .* processed",
        r"transaction .* completed",
        r"statement .* available",
        r"credited to .* account",
        r"successfully .* payment"
    ]

    benign_financial_matches = sum(
        1 for pattern in benign_financial_patterns
        if re.search(pattern, message_lower)
    )

    if (
        benign_financial_matches >= 1
        and "OTP" not in detected
        and "Password" not in detected
        and "Card Credentials" not in detected
        and "Suspicious Link" not in detected
        and "Payment" not in detected
        and "Prize" not in detected
        and "KYC" not in detected
    ):
        risk_score = min(risk_score, 35)

    # --------------------------------------------------
    # LEGITIMATE FINANCIAL NOTIFICATION CONTEXT
    # Prevent normal completed/credited notifications
    # from being treated as scams.
    # --------------------------------------------------

    benign_financial_patterns = [
        r"salary .* credited",
        r"salary .* received",
        r"payment .* received",
        r"payment .* successful",
        r"payment .* processed",
        r"transaction .* completed",
        r"transaction .* successful",
        r"statement .* available",
        r"credited to .* account",
        r"successfully .* payment"
    ]

    benign_financial_matches = sum(
        1 for pattern in benign_financial_patterns
        if re.search(pattern, message_lower)
    )

    # Only suppress the risk when the message is a normal
    # completed/received notification and does NOT contain
    # strong scam indicators.
    strong_scam_indicators = (
        "OTP",
        "Password",
        "Card Credentials",
        "Suspicious Link",
        "Prize",
        "KYC",
        "Refund"
    )

    if (
        benign_financial_matches >= 1
        and not any(item in detected for item in strong_scam_indicators)
        and "Urgency" not in detected
        and "Account Threat" not in detected
    ):
        risk_score = min(risk_score, 35)

        # Remove generic banking warning for completed/credited
        # legitimate financial notifications.
        detected.pop("Banking", None)

    # --------------------------------------------------
    # FINAL CLASSIFICATION
    # Keep prediction and risk level consistent.
    # --------------------------------------------------

    if risk_score >= 70:
        prediction = "scam"
        risk_level = "HIGH RISK"

    elif risk_score >= 45:
        prediction = "suspicious"
        risk_level = "MEDIUM RISK"

    else:
        prediction = "safe"
        risk_level = "LOW RISK"


    # Keep prediction and risk level consistent.
    # --------------------------------------------------

    if risk_score >= 70:
        prediction = "scam"
        risk_level = "HIGH RISK"

    elif risk_score >= 45:
        prediction = "suspicious"
        risk_level = "MEDIUM RISK"

    else:
        prediction = "safe"
        risk_level = "LOW RISK"


    # Keep prediction and risk level consistent.
    # --------------------------------------------------

    if risk_score >= 70:
        prediction = "scam"
        risk_level = "HIGH RISK"

    elif risk_score >= 45:
        prediction = "suspicious"
        risk_level = "MEDIUM RISK"

    else:
        prediction = "safe"
        risk_level = "LOW RISK"

    # --------------------------------------------------
    # EXPLAINABLE AI WARNINGS
    # --------------------------------------------------

    warning_signs = []

    readable = {
        "OTP": "Requests an OTP or verification code",
        "Password": "Requests a password or passcode",
        "Card Credentials": "Requests sensitive card credentials",
        "Banking": "References banking or financial accounts",
        "Account Threat": "Uses an account-blocking or compromise threat",
        "Verification": "Requests identity or account verification",
        "Login": "Requests or redirects toward login",
        "Account Security Alert": "Uses a new-device or unexpected-sign-in security alert",
        "Suspicious Link": "Contains suspicious link-related language",
        "Payment": "Requests payment, transfer, or money",
        "Refund": "Uses a refund or cashback theme",
        "KYC": "Uses KYC/PAN verification language",
        "Urgency": "Creates urgency or pressure to act quickly",
        "Prize": "Uses a prize, reward, lottery, or unexpected-money theme",
        "Delivery": "Contains package/delivery language"
    }

    for category in detected:
        warning_signs.append(readable[category])

    if not warning_signs:
        warning_signs.append(
            "No major suspicious security signals detected."
        )

    return (
        prediction,
        risk_score,
        risk_level,
        warning_signs
    )

def analyze_url(url):

    suspicious_words = [
        "login",
        "verify",
        "secure",
        "account",
        "update",
        "bank",
        "bonus",
        "prize",
        "claim",
        "free"
    ]

    score = 0
    warning_signs = []

    parsed_url = urlparse(url)

    if parsed_url.scheme != "https":
        score += 20
        warning_signs.append("Website is not using HTTPS")

    url_lower = url.lower()

    for word in suspicious_words:
        if word in url_lower:
            score += 10
            warning_signs.append(
                "Suspicious word found: " + word
            )

    if len(url) > 75:
        score += 10
        warning_signs.append(
            "Unusually long URL"
        )

    if "@" in url:
        score += 20
        warning_signs.append(
            "URL contains @ symbol"
        )

    score = min(score, 100)

    if score >= 70:
        risk_level = "HIGH RISK"
    elif score >= 40:
        risk_level = "MEDIUM RISK"
    else:
        risk_level = "LOW RISK"

    return score, risk_level, warning_signs

@app.route("/")
def home():

    return """
<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<meta name="viewport" content="width=device-width, initial-scale=1.0">

<title>ScamShield Pro | AI Cybersecurity</title>

<style>

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {

    font-family:
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        Arial,
        sans-serif;

    background:
        radial-gradient(
            circle at 15% 20%,
            rgba(37,99,235,0.18),
            transparent 30%
        ),
        radial-gradient(
            circle at 85% 10%,
            rgba(124,58,237,0.16),
            transparent 30%
        ),
        #f8fafc;

    color: #0f172a;

    min-height: 100vh;

}


/* =========================
   NAVBAR
========================= */

.navbar {

    height: 72px;

    padding: 0 7%;

    display: flex;

    align-items: center;

    justify-content: space-between;

    background: rgba(15,23,42,0.96);

    color: white;

    border-bottom: 1px solid rgba(255,255,255,0.08);

}

.brand {

    display: flex;

    align-items: center;

    gap: 12px;

    font-size: 22px;

    font-weight: 700;

}

.brand-icon {

    width: 42px;

    height: 42px;

    display: flex;

    align-items: center;

    justify-content: center;

    border-radius: 12px;

    background:
        linear-gradient(
            135deg,
            #2563eb,
            #7c3aed
        );

    font-size: 22px;

}

.brand span {

    color: #60a5fa;

}

.status {

    display: flex;

    align-items: center;

    gap: 8px;

    font-size: 13px;

    color: #cbd5e1;

}

.status-dot {

    width: 8px;

    height: 8px;

    border-radius: 50%;

    background: #22c55e;

}


/* =========================
   HERO
========================= */

.hero {

    max-width: 1150px;

    margin: auto;

    padding: 75px 20px 40px;

    text-align: center;

}

.badge {

    display: inline-flex;

    align-items: center;

    gap: 8px;

    padding: 9px 15px;

    border-radius: 999px;

    background: #eff6ff;

    border: 1px solid #dbeafe;

    color: #2563eb;

    font-size: 13px;

    font-weight: 700;

    margin-bottom: 22px;

}

.hero h1 {

    font-size: clamp(38px, 6vw, 68px);

    line-height: 1.05;

    letter-spacing: -2px;

    max-width: 900px;

    margin: auto;

}

.hero h1 span {

    background:
        linear-gradient(
            90deg,
            #2563eb,
            #7c3aed
        );

    -webkit-background-clip: text;

    color: transparent;

}

.hero p {

    max-width: 720px;

    margin: 24px auto 0;

    font-size: 18px;

    line-height: 1.7;

    color: #64748b;

}


/* =========================
   TRUST BAR
========================= */

.trust {

    display: flex;

    justify-content: center;

    gap: 35px;

    flex-wrap: wrap;

    margin-top: 30px;

    color: #64748b;

    font-size: 13px;

}

.trust div {

    display: flex;

    align-items: center;

    gap: 7px;

}


/* =========================
   SCANNER
========================= */

.scanner-wrapper {

    max-width: 900px;

    margin: 25px auto 70px;

    padding: 0 20px;

}

.scanner {

    background: rgba(255,255,255,0.94);

    border: 1px solid #e2e8f0;

    border-radius: 24px;

    padding: 35px;

    box-shadow:
        0 25px 70px rgba(15,23,42,0.12);

}

.scanner-header {

    display: flex;

    align-items: center;

    gap: 15px;

    margin-bottom: 28px;

}

.scanner-icon {

    width: 52px;

    height: 52px;

    display: flex;

    align-items: center;

    justify-content: center;

    background: #eff6ff;

    border-radius: 14px;

    font-size: 27px;

}

.scanner-header h2 {

    font-size: 22px;

}

.scanner-header p {

    color: #64748b;

    font-size: 13px;

    margin-top: 4px;

}

label {

    display: block;

    font-size: 14px;

    font-weight: 700;

    margin-bottom: 9px;

}

textarea,
input {

    width: 100%;

    border: 1px solid #cbd5e1;

    border-radius: 14px;

    background: #f8fafc;

    padding: 16px;

    font-family: inherit;

    font-size: 15px;

    transition: 0.2s;

}

textarea {

    min-height: 155px;

    resize: vertical;

}

textarea:focus,
input:focus {

    outline: none;

    border-color: #2563eb;

    background: white;

    box-shadow:
        0 0 0 4px rgba(37,99,235,0.10);

}

.field {

    margin-bottom: 22px;

}

.optional {

    color: #94a3b8;

    font-weight: 400;

}


/* =========================
   BUTTON
========================= */

.scan-button {

    width: 100%;

    border: none;

    border-radius: 14px;

    padding: 17px;

    background:
        linear-gradient(
            135deg,
            #2563eb,
            #4f46e5
        );

    color: white;

    font-size: 16px;

    font-weight: 800;

    cursor: pointer;

    transition: 0.2s;

    box-shadow:
        0 10px 25px rgba(37,99,235,0.25);

}

.scan-button:hover {

    transform: translateY(-2px);

    box-shadow:
        0 15px 30px rgba(37,99,235,0.30);

}

.scan-button:active {

    transform: translateY(0);

}


/* =========================
   FEATURES
========================= */

.features {

    max-width: 1100px;

    margin: auto;

    padding: 0 20px 75px;

    display: grid;

    grid-template-columns:
        repeat(3, 1fr);

    gap: 20px;

}

.feature {

    background: white;

    border: 1px solid #e2e8f0;

    border-radius: 18px;

    padding: 28px;

    transition: 0.2s;

}

.feature:hover {

    transform: translateY(-4px);

    box-shadow:
        0 15px 35px rgba(15,23,42,0.09);

}

.feature-icon {

    width: 48px;

    height: 48px;

    display: flex;

    align-items: center;

    justify-content: center;

    border-radius: 13px;

    background: #f1f5f9;

    font-size: 23px;

    margin-bottom: 18px;

}

.feature h3 {

    margin-bottom: 8px;

}

.feature p {

    color: #64748b;

    font-size: 14px;

    line-height: 1.6;

}


/* =========================
   FOOTER
========================= */

.footer {

    background: #0f172a;

    color: #94a3b8;

    padding: 30px 20px;

    text-align: center;

    font-size: 13px;

}

.footer strong {

    color: white;

}


/* =========================
   MOBILE
========================= */

@media (max-width: 700px) {

    .navbar {

        padding: 0 18px;

    }

    .status {

        display: none;

    }

    .hero {

        padding-top: 55px;

    }

    .hero h1 {

        letter-spacing: -1px;

    }

    .scanner {

        padding: 23px;

    }

    .features {

        grid-template-columns: 1fr;

    }

    .trust {

        gap: 15px;

    }

}

</style>

</head>


<body>


<!-- NAVIGATION -->

<nav class="navbar">

    <div class="brand">

        <div class="brand-icon">
            🛡️
        </div>

        <div>
            ScamShield <span>Pro</span>
        </div>

    </div>


    <div class="status">

        <div class="status-dot"></div>

        AI Security Engine Active

    </div>

</nav>



<!-- HERO -->

<section class="hero">

    <div class="badge">

        ✨ AI-POWERED THREAT DETECTION

    </div>


    <h1>

        Detect Scams Before

        <span>You Click.</span>

    </h1>


    <p>

        Analyze suspicious messages and URLs using
        machine learning and security intelligence.
        Understand the risk before you take action.

    </p>


    <div class="trust">

        <div>
            ✓ Machine Learning
        </div>

        <div>
            ✓ Risk Analysis
        </div>

        <div>
            ✓ Explainable Results
        </div>

        <div>
            ✓ URL Security
        </div>

    </div>

</section>



<!-- SCANNER -->

<div class="scanner-wrapper">

    <div class="scanner">

        <div class="scanner-header">

            <div class="scanner-icon">
                🔍
            </div>

            <div>

                <h2>
                    Threat Scanner
                </h2>

                <p>
                    Scan a suspicious message or website
                </p>

            </div>

        </div>


        <form action="/scan" method="POST">


            <div class="field">

                <label>
                    💬 Suspicious Message
                </label>

                <textarea
                    name="message"
                    placeholder="Paste the suspicious message here..."
                    required
                ></textarea>

            </div>


            <div class="field">

                <label>

                    🔗 Suspicious URL

                    <span class="optional">
                        (optional)
                    </span>

                </label>

                <input
                    type="url"
                    name="url"
                    placeholder="https://example.com/login"
                >

            </div>


            <button
                class="scan-button"
                type="submit"
            >

                🔍 ANALYZE THREAT

            </button>


        </form>

    </div>

</div>



<!-- FEATURES -->

<section class="features">


    <div class="feature">

        <div class="feature-icon">
            🤖
        </div>

        <h3>
            AI Detection
        </h3>

        <p>
            Machine learning analyzes message
            patterns to identify potential scams.
        </p>

    </div>


    <div class="feature">

        <div class="feature-icon">
            🔗
        </div>

        <h3>
            URL Intelligence
        </h3>

        <p>
            Detect suspicious URL structures,
            risky words and unsafe patterns.
        </p>

    </div>


    <div class="feature">

        <div class="feature-icon">
            🧠
        </div>

        <h3>
            Explainable Security
        </h3>

        <p>
            See the warning signs behind every
            security decision.
        </p>

    </div>


</section>



<footer class="footer">

    <strong>🛡️ ScamShield Pro</strong>

    <br><br>

    AI-Powered Scam, Phishing & Fraud Detection Platform

</footer>


</body>

</html>
"""


@app.route("/scan", methods=["POST"])
def scan():

    message = request.form["message"]
    url = request.form.get("url", "").strip()

    prediction, risk_score, risk_level, warning_signs = analyze_message(message)

    url_score = None
    url_risk_level = None
    url_warnings = []

    if url:
        url_score, url_risk_level, url_warnings = analyze_url(url)

    if risk_level == "HIGH RISK":
        risk_class = "high"
        risk_icon = "🚨"
    elif risk_level == "MEDIUM RISK":
        risk_class = "medium"
        risk_icon = "⚠️"
    else:
        risk_class = "low"
        risk_icon = "✅"

    warning_html = ""

    if warning_signs:
        for warning in warning_signs:
            warning_html += f"<li>⚠️ {warning}</li>"
    else:
        warning_html = "<li>✅ No major message warning signs detected.</li>"

    url_html = ""

    if url:

        if url_risk_level == "HIGH RISK":
            url_class = "high"
            url_icon = "🚨"
        elif url_risk_level == "MEDIUM RISK":
            url_class = "medium"
            url_icon = "⚠️"
        else:
            url_class = "low"
            url_icon = "✅"

        url_warning_html = ""

        if url_warnings:
            for warning in url_warnings:
                url_warning_html += f"<li>⚠️ {warning}</li>"
        else:
            url_warning_html = "<li>✅ No major URL warning signs detected.</li>"

        url_html = f"""
        <div class="card">
            <div class="card-title">🔗 URL Security Analysis</div>

            <div class="url-box">
                {url}
            </div>

            <div class="risk-row">
                <div>
                    <span class="label">URL Risk Score</span>
                    <span class="score">{url_score}/100</span>
                </div>

                <div class="badge {url_class}">
                    {url_icon} {url_risk_level}
                </div>
            </div>

            <h3>⚠️ URL Warning Signs</h3>

            <ul>
                {url_warning_html}
            </ul>
        </div>
        """

    return f"""
    <!DOCTYPE html>

    <html>

    <head>

        <meta charset="UTF-8">

        <meta name="viewport" content="width=device-width, initial-scale=1.0">

        <title>Scan Result - ScamShield Pro</title>

        <style>

            * {{
                box-sizing: border-box;
            }}

            body {{
                margin: 0;
                font-family: Arial, sans-serif;
                background: #eef3f8;
                color: #172033;
            }}

            .navbar {{
                background: #0f172a;
                color: white;
                padding: 20px 40px;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }}

            .logo {{
                font-size: 24px;
                font-weight: bold;
            }}

            .security {{
                font-size: 14px;
                opacity: 0.8;
            }}

            .container {{
                max-width: 900px;
                margin: 40px auto;
                padding: 0 20px;
            }}

            .heading {{
                text-align: center;
                margin-bottom: 30px;
            }}

            .heading h1 {{
                font-size: 34px;
                margin-bottom: 10px;
                color: #0f172a;
            }}

            .heading p {{
                color: #64748b;
            }}

            .card {{
                background: white;
                padding: 30px;
                border-radius: 18px;
                margin-bottom: 25px;
                box-shadow: 0 8px 30px rgba(15,23,42,0.08);
            }}

            .card-title {{
                font-size: 22px;
                font-weight: bold;
                margin-bottom: 20px;
            }}

            .message-box {{
                background: #f8fafc;
                border-left: 5px solid #2563eb;
                padding: 20px;
                border-radius: 10px;
                line-height: 1.6;
                margin-bottom: 25px;
            }}

            .risk-panel {{
                text-align: center;
                padding: 25px;
                border-radius: 15px;
                background: #f8fafc;
            }}

            .risk-icon {{
                font-size: 48px;
            }}

            .score {{
                display: block;
                font-size: 38px;
                font-weight: bold;
                margin: 10px 0;
            }}

            .badge {{
                display: inline-block;
                padding: 10px 18px;
                border-radius: 30px;
                font-weight: bold;
                margin-top: 10px;
            }}

            .high {{
                background: #fee2e2;
                color: #b91c1c;
            }}

            .medium {{
                background: #fef3c7;
                color: #92400e;
            }}

            .low {{
                background: #dcfce7;
                color: #166534;
            }}

            .warning-list {{
                padding-left: 20px;
            }}

            li {{
                margin: 12px 0;
            }}

            .risk-row {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                background: #f8fafc;
                padding: 20px;
                border-radius: 12px;
                margin-top: 20px;
            }}

            .label {{
                display: block;
                color: #64748b;
                font-size: 14px;
            }}

            .url-box {{
                background: #f1f5f9;
                padding: 15px;
                border-radius: 10px;
                word-break: break-all;
                font-family: monospace;
            }}

            .safety {{
                background: #eff6ff;
                border-left: 5px solid #2563eb;
            }}

            .back {{
                display: block;
                width: fit-content;
                margin: 30px auto;
                padding: 14px 25px;
                background: #2563eb;
                color: white;
                text-decoration: none;
                border-radius: 10px;
                font-weight: bold;
            }}

            .back:hover {{
                background: #1d4ed8;
            }}

            @media (max-width: 600px) {{

                .navbar {{
                    padding: 18px;
                }}

                .security {{
                    display: none;
                }}

                .heading h1 {{
                    font-size: 28px;
                }}

                .card {{
                    padding: 20px;
                }}

                .risk-row {{
                    flex-direction: column;
                    gap: 15px;
                    text-align: center;
                }}

            }}

        </style>

    </head>

    <body>

        <div class="navbar">

            <div class="logo">🛡️ ScamShield Pro</div>

            <div class="security">
                AI-Powered Cybersecurity Platform
            </div>

        </div>

        <div class="container">

            <div class="heading">

                <h1>Security Scan Complete</h1>

                <p>AI analysis of your submitted content</p>

            </div>

            <div class="card">

                <div class="card-title">
                    💬 Message Analysis
                </div>

                <div class="message-box">
                    {message}
                </div>

                <div class="risk-panel">

                    <div class="risk-icon">
                        {risk_icon}
                    </div>

                    <div>AI Prediction</div>

                    <div class="score">
                        {prediction.upper()}
                    </div>

                    <div class="badge {risk_class}">
                        {risk_icon} {risk_level}
                    </div>

                    <div style="margin-top:15px;">
                        Risk Score: <strong>{risk_score}/100</strong>
                    </div>

                </div>

            </div>

            <div class="card">

                <div class="card-title">
                    ⚠️ Detected Warning Signs
                </div>

                <ul class="warning-list">
                    {warning_html}
                </ul>

            </div>

            {url_html}

            <div class="card safety">

                <div class="card-title">
                    🛡️ Safety Recommendation
                </div>

                <p>
                    Never share OTPs, passwords, banking credentials,
                    card details, or payment information with unknown
                    people or suspicious websites.
                </p>

                <p>
                    If you receive a suspicious message, verify the
                    sender through an official source before taking action.
                </p>

            </div>

            <a class="back" href="/">
                🔄 Scan Another Message
            </a>

        </div>

    </body>

    </html>
    """


if __name__ == "__main__":
    app.run(debug=True)
