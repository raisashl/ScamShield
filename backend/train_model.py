import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

print("Loading ScamShield datasets...")

# Original training dataset
original = pd.read_csv("data/train.csv")
original = original[["text", "label"]].dropna()

# ScamShield-specific examples
custom = pd.read_csv("data/extra_scam_data.csv")
custom = custom[["text", "label"]].dropna()

# Combine both datasets
data = pd.concat(
    [original, custom],
    ignore_index=True
)

data["label"] = data["label"].astype(int)

print(f"\nOriginal examples : {len(original)}")
print(f"Custom examples   : {len(custom)}")
print(f"Total examples    : {len(data)}")

print("\nLabel distribution:")
print(data["label"].value_counts())

X = data["text"]
y = data["label"]

# Keep a portion aside for evaluation
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print(f"\nTraining examples: {len(X_train)}")
print(f"Testing examples : {len(X_test)}")

# TF-IDF + Logistic Regression
model = Pipeline([
    (
        "tfidf",
        TfidfVectorizer(
            lowercase=True,
            strip_accents="unicode",
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
            class_weight="balanced"
        )
    )
])

print("\nTraining improved ScamShield NLP model...")

model.fit(X_train, y_train)

# Test model
predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)

print("\n==============================")
print("SCAMSHIELD MODEL RESULTS")
print("==============================")

print(f"\nAccuracy: {accuracy * 100:.2f}%")

print("\nClassification Report:")

print(
    classification_report(
        y_test,
        predictions,
        target_names=["Legitimate", "Scam"]
    )
)

print("\nConfusion Matrix:")

print(confusion_matrix(y_test, predictions))

# Save model
joblib.dump(model, "scamshield_model.pkl")

print("\n==============================")
print("Improved model saved!")
print("File: scamshield_model.pkl")
print("==============================")