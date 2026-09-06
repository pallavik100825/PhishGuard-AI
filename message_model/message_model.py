import joblib
import os


# ============================================================
# MODEL PATH
# ============================================================

MODEL_PATH = "models/message_model.pkl"


# ============================================================
# LOAD MODEL
# ============================================================

if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(
        f"Message model not found: {MODEL_PATH}"
    )


model_package = joblib.load(MODEL_PATH)

model = model_package["model"]


# ============================================================
# MESSAGE ANALYSIS
# ============================================================

def analyze_message(message):

    message = str(message).strip()

    if not message:
        return {
            "result": "NO MESSAGE",
            "risk_score": 0.0,
            "threat_level": "SAFE",
            "probability": 0.0
        }


    # --------------------------------------------------------
    # Prediction
    # --------------------------------------------------------

    prediction = model.predict(
        [message]
    )[0]


    # --------------------------------------------------------
    # Probability
    # --------------------------------------------------------

    probabilities = model.predict_proba(
        [message]
    )[0]


    spam_index = list(
        model.classes_
    ).index(1)


    spam_probability = probabilities[
        spam_index
    ]


    risk_score = round(
        spam_probability * 100,
        2
    )


    # --------------------------------------------------------
    # Threat classification
    # --------------------------------------------------------

    if risk_score >= 80:

        result = "SCAM / SPAM DETECTED"
        threat_level = "HIGH"

    elif risk_score >= 50:

        result = "SCAM / SPAM DETECTED"
        threat_level = "MEDIUM"

    elif risk_score >= 20:

        result = "MESSAGE APPEARS SUSPICIOUS"
        threat_level = "LOW"

    else:

        result = "MESSAGE APPEARS SAFE"
        threat_level = "SAFE"


    # --------------------------------------------------------
    # Return analysis
    # --------------------------------------------------------

    return {

        "result": result,

        "risk_score": risk_score,

        "threat_level": threat_level,

        "probability": risk_score,

        "prediction": int(prediction)
    }