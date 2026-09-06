import os
import sys
import re
import joblib
import pandas as pd

from urllib.parse import urlparse

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)


# ============================================================
# PHISHGUARD AI - URL MODEL V4
# Random Forest + Structural URL Features
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

DATA_PATH = os.path.join(
    BASE_DIR,
    "data",
    "PhiUSIIL_Phishing_URL_Dataset.csv"
)

MODEL_DIR = os.path.join(
    BASE_DIR,
    "models"
)

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "url_model.pkl"
)


# ============================================================
# MODEL FEATURES
# ============================================================

FEATURE_NAMES = [
    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "TLDLength",
    "NoOfSubDomain",
    "NoOfLettersInURL",
    "NoOfDegitsInURL",
    "NoOfEqualsInURL",
    "NoOfQMarkInURL",
    "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL",
    "IsHTTPS"
]


# ============================================================
# LOAD DATASET
# ============================================================

print("=" * 72)
print("PHISHGUARD AI - URL MODEL V4 TRAINING")
print("=" * 72)

print("\n[1/8] Loading dataset...")

if not os.path.exists(DATA_PATH):

    print("\nERROR: Dataset not found:")
    print(DATA_PATH)

    sys.exit(1)

df = pd.read_csv(DATA_PATH)

print(
    f"Dataset loaded: "
    f"{len(df):,} rows, "
    f"{len(df.columns)} columns"
)


# ============================================================
# VERIFY DATASET
# ============================================================

required_columns = [
    "URL",
    "label"
] + FEATURE_NAMES

missing_columns = [
    column
    for column in required_columns
    if column not in df.columns
]

if missing_columns:

    print("\nERROR: Missing columns:")

    for column in missing_columns:
        print(f"  - {column}")

    sys.exit(1)


# ============================================================
# CLEAN DATA
# ============================================================

print("\n[2/8] Cleaning dataset...")

df = df[
    required_columns
].copy()

df = df.dropna(
    subset=[
        "URL",
        "label"
    ]
)

df["URL"] = (
    df["URL"]
    .astype(str)
    .str.strip()
)

df = df[
    df["URL"] != ""
]

for feature in FEATURE_NAMES:

    df[feature] = pd.to_numeric(
        df[feature],
        errors="coerce"
    )

df[FEATURE_NAMES] = (
    df[FEATURE_NAMES]
    .fillna(0)
)

print(
    f"Clean dataset: "
    f"{len(df):,} URLs"
)


# ============================================================
# TARGET
# ============================================================

print("\n[3/8] Preparing labels...")

# UCI PhiUSIIL:
#
# label = 1 -> legitimate
# label = 0 -> phishing
#
# PhishGuard:
#
# 0 -> legitimate
# 1 -> phishing

y = (
    df["label"] == 0
).astype(int)

X = df[
    FEATURE_NAMES
].copy()


legitimate_count = int(
    (y == 0).sum()
)

phishing_count = int(
    (y == 1).sum()
)

print(
    f"Legitimate : {legitimate_count:,}"
)

print(
    f"Phishing   : {phishing_count:,}"
)


# ============================================================
# TRAIN / TEST SPLIT
# ============================================================

print("\n[4/8] Creating training and testing sets...")

X_train, X_test, y_train, y_test = train_test_split(

    X,
    y,

    test_size=0.20,

    random_state=42,

    stratify=y
)

print(
    f"Training samples : {len(X_train):,}"
)

print(
    f"Testing samples  : {len(X_test):,}"
)


# ============================================================
# RANDOM FOREST
# ============================================================

print("\n[5/8] Building Random Forest model...")

print("\nConfiguration:")

print("  Trees          : 400")

print("  Class weighting: balanced")

print("  Random state   : 42")

print("  Parallel jobs  : all CPU cores")


model = RandomForestClassifier(

    n_estimators=400,

    random_state=42,

    n_jobs=-1,

    class_weight="balanced",

    max_features="sqrt",

    min_samples_leaf=2
)


# ============================================================
# TRAIN
# ============================================================

print("\nTraining V4 model...")

model.fit(
    X_train,
    y_train
)

print(
    "Training completed successfully."
)


# ============================================================
# EVALUATION
# ============================================================

print("\n[6/8] Evaluating model...")

y_pred = model.predict(
    X_test
)

accuracy = accuracy_score(
    y_test,
    y_pred
)

precision = precision_score(
    y_test,
    y_pred,
    zero_division=0
)

recall = recall_score(
    y_test,
    y_pred,
    zero_division=0
)

f1 = f1_score(
    y_test,
    y_pred,
    zero_division=0
)

cm = confusion_matrix(
    y_test,
    y_pred
)


print("\n" + "=" * 72)
print("V4 MODEL PERFORMANCE")
print("=" * 72)

print(
    f"\nAccuracy  : {accuracy * 100:.2f}%"
)

print(
    f"Precision : {precision * 100:.2f}%"
)

print(
    f"Recall    : {recall * 100:.2f}%"
)

print(
    f"F1 Score  : {f1 * 100:.2f}%"
)

print("\nConfusion Matrix:")

print(cm)

print("\nClassification Report:")

print(
    classification_report(
        y_test,
        y_pred,
        target_names=[
            "LEGITIMATE",
            "PHISHING"
        ],
        zero_division=0
    )
)


# ============================================================
# FEATURE IMPORTANCE
# ============================================================

print("\n" + "=" * 72)
print("FEATURE IMPORTANCE")
print("=" * 72)

importance = pd.DataFrame({

    "Feature":
        FEATURE_NAMES,

    "Importance":
        model.feature_importances_

})

importance = importance.sort_values(
    "Importance",
    ascending=False
)

for _, row in importance.iterrows():

    print(
        f"{row['Feature']:<35} "
        f"{row['Importance'] * 100:>7.2f}%"
    )


# ============================================================
# REAL-WORLD SANITY TEST
# ============================================================

print("\n[7/8] Running real-world sanity tests...")


def extract_model_features(url):

    parsed = urlparse(url)

    hostname = (
        parsed.hostname
        or ""
    )

    # --------------------------------------------------------
    # IP detection
    # --------------------------------------------------------

    try:

        parts = hostname.split(".")

        is_ip = int(
            len(parts) == 4
            and all(
                part.isdigit()
                and 0 <= int(part) <= 255
                for part in parts
            )
        )

    except Exception:

        is_ip = 0


    # --------------------------------------------------------
    # Domain length
    # --------------------------------------------------------

    domain_length = len(
        hostname
    )


    # --------------------------------------------------------
    # TLD
    # --------------------------------------------------------

    if is_ip:

        tld_length = 0

    else:

        domain_parts = (
            hostname.split(".")
        )

        if len(domain_parts) >= 2:

            tld_length = len(
                domain_parts[-1]
            )

        else:

            tld_length = 0


    # --------------------------------------------------------
    # Subdomains
    # --------------------------------------------------------

    if is_ip:

        subdomains = 0

    else:

        domain_parts = (
            hostname.split(".")
        )

        subdomains = max(
            0,
            len(domain_parts) - 2
        )


    # --------------------------------------------------------
    # Character counts
    # --------------------------------------------------------

    letters = sum(
        character.isalpha()
        for character in url
    )

    digits = sum(
        character.isdigit()
        for character in url
    )

    equals = url.count("=")

    question_marks = url.count("?")

    ampersands = url.count("&")

    special_characters = len(
        re.findall(
            r"[^a-zA-Z0-9:/?&=._#%-]",
            url
        )
    )

    https = int(
        parsed.scheme.lower()
        == "https"
    )


    return {

        "URLLength":
            len(url),

        "DomainLength":
            domain_length,

        "IsDomainIP":
            is_ip,

        "TLDLength":
            tld_length,

        "NoOfSubDomain":
            subdomains,

        "NoOfLettersInURL":
            letters,

        "NoOfDegitsInURL":
            digits,

        "NoOfEqualsInURL":
            equals,

        "NoOfQMarkInURL":
            question_marks,

        "NoOfAmpersandInURL":
            ampersands,

        "NoOfOtherSpecialCharsInURL":
            special_characters,

        "IsHTTPS":
            https
    }


# ------------------------------------------------------------
# Test URLs
# ------------------------------------------------------------

sanity_urls = [

    # Legitimate
    (
        "https://www.google.com",
        0
    ),

    (
        "https://www.google.com/search?q=python",
        0
    ),

    (
        "https://example.com",
        0
    ),

    (
        "https://github.com",
        0
    ),

    (
        "https://www.microsoft.com",
        0
    ),

    (
        "https://www.apple.com",
        0
    ),

    (
        "https://www.amazon.com",
        0
    ),

    (
        "https://www.wikipedia.org",
        0
    ),

    (
        "https://stackoverflow.com/questions",
        0
    ),

    (
        "https://www.python.org/downloads/",
        0
    ),

    # Phishing
    (
        "http://192.168.1.100/login/verify/account",
        1
    ),

    (
        "http://paypal-security-login.example.com/verify",
        1
    ),

    (
        "http://secure-account-login-verify.example.net",
        1
    ),

    (
        "http://account-security-confirm-password.example.com/login",
        1
    ),

    (
        "http://192.168.0.10/banking/login",
        1
    )
]


print("\n" + "-" * 72)

correct = 0

for url, expected in sanity_urls:

    feature_values = (
        extract_model_features(url)
    )

    test_data = pd.DataFrame(
        [
            feature_values
        ],
        columns=FEATURE_NAMES
    )

    probability = model.predict_proba(
        test_data
    )[0][1]

    prediction = int(
        probability >= 0.50
    )

    expected_name = (
        "LEGITIMATE"
        if expected == 0
        else "PHISHING"
    )

    predicted_name = (
        "LEGITIMATE"
        if prediction == 0
        else "PHISHING"
    )

    passed = (
        prediction == expected
    )

    if passed:

        correct += 1

    status = (
        "PASS"
        if passed
        else "FAIL"
    )

    print(
        f"\n[{status}] {url}"
    )

    print(
        f"Expected   : {expected_name}"
    )

    print(
        f"Predicted  : {predicted_name}"
    )

    print(
        f"Probability: {probability * 100:.2f}%"
    )


sanity_accuracy = (
    correct /
    len(sanity_urls)
) * 100


print("\n" + "-" * 72)

print(
    f"Sanity Test Accuracy: "
    f"{sanity_accuracy:.2f}% "
    f"({correct}/{len(sanity_urls)})"
)


# ============================================================
# SAVE MODEL
# ============================================================

print("\n[8/8] Saving V4 model...")

os.makedirs(
    MODEL_DIR,
    exist_ok=True
)


model_package = {

    "model":
        model,

    "feature_names":
        FEATURE_NAMES,

    "model_type":
        "Random Forest Structural URL Classifier",

    "version":
        "4.0",

    "classes": {

        0:
            "LEGITIMATE",

        1:
            "PHISHING"
    },

    "training_metrics": {

        "accuracy":
            round(
                accuracy,
                6
            ),

        "precision":
            round(
                precision,
                6
            ),

        "recall":
            round(
                recall,
                6
            ),

        "f1":
            round(
                f1,
                6
            )
    }
}


joblib.dump(
    model_package,
    MODEL_PATH
)


print("\n" + "=" * 72)
print("PHISHGUARD AI URL MODEL V4 SAVED")
print("=" * 72)

print(
    f"\nModel path:\n{MODEL_PATH}"
)

print(
    "\nArchitecture:"
)

print(
    "12 structural URL features"
)

print(
    "\nClassifier:"
)

print(
    "Random Forest"
)

print(
    "\nVersion:"
)

print(
    "4.0"
)

print(
    "\nTraining complete."
)