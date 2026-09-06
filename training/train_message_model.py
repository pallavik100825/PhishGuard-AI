import os
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)


# ============================================================
# PATHS
# ============================================================

DATA_PATH = "data/SMSSpamCollection"
MODEL_PATH = "models/message_model.pkl"


# ============================================================
# LOAD DATASET
# ============================================================

print("\nLoading SMS Spam Collection dataset...")

df = pd.read_csv(
    DATA_PATH,
    sep="\t",
    header=None,
    names=["label", "message"],
    encoding="latin-1"
)


print(f"Total messages: {len(df)}")


# ============================================================
# CLEAN DATASET
# ============================================================

df = df[["label", "message"]].dropna()

# Remove duplicate messages
df = df.drop_duplicates(
    subset=["message"]
).reset_index(drop=True)


# Convert labels:
#
# ham  = 0 = legitimate
# spam = 1 = suspicious/scam
#
df["target"] = (
    df["label"]
    .str.lower()
    .map({
        "ham": 0,
        "spam": 1
    })
)


# Remove unexpected labels if any
df = df.dropna(
    subset=["target"]
)


print(f"Messages after cleaning: {len(df)}")

print("\nClass distribution:")

print(
    df["label"].value_counts()
)


# ============================================================
# INPUT AND TARGET
# ============================================================

X = df["message"]

y = df["target"].astype(int)


# ============================================================
# TRAIN / TEST SPLIT
# ============================================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


print("\nTraining messages:", len(X_train))
print("Testing messages:", len(X_test))


# ============================================================
# NLP PIPELINE
# ============================================================

pipeline = Pipeline([

    (
        "tfidf",
        TfidfVectorizer(
            lowercase=True,
            stop_words="english",
            ngram_range=(1, 2),
            min_df=2,
            max_df=0.95,
            sublinear_tf=True
        )
    ),

    (
        "classifier",
        LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            random_state=42
        )
    )
])


# ============================================================
# TRAIN MODEL
# ============================================================

print("\nTraining TF-IDF + Logistic Regression model...")

pipeline.fit(
    X_train,
    y_train
)


print("Training completed.")


# ============================================================
# PREDICTIONS
# ============================================================

y_pred = pipeline.predict(
    X_test
)


probabilities = pipeline.predict_proba(
    X_test
)

# Class 1 = spam
spam_index = list(
    pipeline.classes_
).index(1)

spam_probability = probabilities[
    :,
    spam_index
]


# ============================================================
# EVALUATION
# ============================================================

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

matrix = confusion_matrix(
    y_test,
    y_pred
)


print("\n")
print("=" * 60)
print("MESSAGE PHISHING / SCAM MODEL RESULTS")
print("=" * 60)

print(
    f"Accuracy : {accuracy * 100:.2f}%"
)

print(
    f"Precision: {precision * 100:.2f}%"
)

print(
    f"Recall   : {recall * 100:.2f}%"
)

print(
    f"F1 Score : {f1 * 100:.2f}%"
)


print("\nConfusion Matrix:")
print(matrix)


print("\nClassification Report:")
print(
    classification_report(
        y_test,
        y_pred,
        target_names=[
            "Legitimate",
            "Spam / Scam"
        ],
        zero_division=0
    )
)


# ============================================================
# SAVE MODEL
# ============================================================

os.makedirs(
    "models",
    exist_ok=True
)

model_package = {

    "model": pipeline,

    "classes": {
        0: "LEGITIMATE",
        1: "SPAM / SCAM"
    }

}


joblib.dump(
    model_package,
    MODEL_PATH
)


print("=" * 60)

print(
    f"Model saved successfully to: {MODEL_PATH}"
)

print("=" * 60)

print("\nNLP model training completed successfully.")