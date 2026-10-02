"""
train_model.py
---------------
Loads the feature dataset produced by data_collection/build_dataset.py,
trains and compares several classifiers, evaluates them properly, and
saves the best-performing model to disk.

Usage:
    python train_model.py --data ../data/dataset.csv --out-dir ../models

    # With hyperparameter tuning on the best baseline model (slower):
    python train_model.py --data ../data/dataset.csv --out-dir ../models --tune
"""

import argparse
import json
import os
import sys
import warnings

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GridSearchCV, train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier

try:
    from xgboost import XGBClassifier
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False

warnings.filterwarnings("ignore")

RANDOM_STATE = 42


def load_dataset(path: str):
    """
    Load the feature CSV and split into X (features), y (labels).
    Non-feature columns (url, extraction_error, error_message) are
    dropped. Rows where feature extraction failed are dropped too.
    """
    df = pd.read_csv(path)

    if "extraction_error" in df.columns:
        before = len(df)
        df = df[df["extraction_error"] != 1]
        dropped = before - len(df)
        if dropped:
            print(f"Dropped {dropped} rows with failed feature extraction.")

    drop_cols = [c for c in ["url", "extraction_error", "error_message"] if c in df.columns]
    df = df.drop(columns=drop_cols)

    if "label" not in df.columns:
        print("ERROR: dataset has no 'label' column.", file=sys.stderr)
        sys.exit(1)

    y = df["label"].map({"phishing": 1, "legitimate": 0})
    if y.isna().any():
        bad = df["label"][y.isna()].unique()
        print(f"ERROR: unexpected label values found: {bad}. Expected 'phishing'/'legitimate'.", file=sys.stderr)
        sys.exit(1)

    X = df.drop(columns=["label"])

    # Any remaining non-numeric columns would break sklearn — coerce/drop them
    non_numeric = X.select_dtypes(exclude=[np.number]).columns.tolist()
    if non_numeric:
        print(f"Dropping non-numeric columns not usable as features: {non_numeric}")
        X = X.drop(columns=non_numeric)

    # -1 sentinels from domain/content features (tier 2/3) are legitimate
    # "unknown" signals, not missing data to impute — leave them as-is,
    # tree-based models handle them fine as just another value.
    X = X.fillna(-1)

    return X, y


def get_models(y_train=None):
    """
    Baseline models with sane default hyperparameters.

    class_weight="balanced" (and XGBoost's scale_pos_weight) reweight
    the loss function so the minority class counts for more per
    example. This matters a lot here: phishing feeds (PhishTank,
    OpenPhish) are usually far larger than a legitimate-URL sample, and
    without balancing, a model trained on e.g. 75k phishing vs. 3k
    legitimate examples will systematically over-predict "phishing" on
    anything unfamiliar — including real, well-known legitimate sites
    whose URL shape it just didn't see much of during training.
    """
    models = {
        "Logistic Regression": LogisticRegression(
            max_iter=1000, random_state=RANDOM_STATE, class_weight="balanced"
        ),
        "Decision Tree": DecisionTreeClassifier(
            random_state=RANDOM_STATE, max_depth=10, class_weight="balanced"
        ),
        "Random Forest": RandomForestClassifier(
            n_estimators=200, random_state=RANDOM_STATE, n_jobs=-1, class_weight="balanced"
        ),
        "SVM (RBF)": SVC(probability=True, random_state=RANDOM_STATE, class_weight="balanced"),
    }
    if HAS_XGBOOST:
        # XGBoost has no class_weight param; scale_pos_weight = (# negative / # positive)
        # achieves the same effect. Falls back to 1 (no reweighting) if
        # y_train wasn't passed in, but callers below always pass it.
        scale_pos_weight = 1.0
        if y_train is not None:
            n_pos = (y_train == 1).sum()
            n_neg = (y_train == 0).sum()
            if n_pos > 0:
                scale_pos_weight = n_neg / n_pos
        models["XGBoost"] = XGBClassifier(
            n_estimators=200,
            random_state=RANDOM_STATE,
            eval_metric="logloss",
            n_jobs=-1,
            scale_pos_weight=scale_pos_weight,
        )
    else:
        print("NOTE: xgboost not installed — skipping. `pip install xgboost` to include it.")
    return models


def evaluate_model(name, model, X_test, y_test):
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1] if hasattr(model, "predict_proba") else None

    metrics = {
        "model": name,
        "accuracy": accuracy_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred, zero_division=0),
        "recall": recall_score(y_test, y_pred, zero_division=0),
        "f1": f1_score(y_test, y_pred, zero_division=0),
    }
    if y_proba is not None:
        metrics["roc_auc"] = roc_auc_score(y_test, y_proba)

    cm = confusion_matrix(y_test, y_pred)
    return metrics, cm, y_pred


def print_confusion_matrix(cm, name):
    tn, fp, fn, tp = cm.ravel()
    print(f"\n  Confusion matrix ({name}):")
    print(f"                  Predicted Legit   Predicted Phishing")
    print(f"  Actual Legit         {tn:6d}              {fp:6d}   <- false positives (legit flagged as phishing)")
    print(f"  Actual Phishing      {fn:6d}              {tp:6d}   <- {fn} false negatives (phishing MISSED, security risk)")


def main():
    parser = argparse.ArgumentParser(description="Train and compare phishing detection models.")
    parser.add_argument("--data", default="../data/dataset.csv", help="Path to feature dataset CSV")
    parser.add_argument("--out-dir", default="../models", help="Directory to save the trained model")
    parser.add_argument("--test-size", type=float, default=0.2, help="Fraction of data held out for testing")
    parser.add_argument("--tune", action="store_true", help="Run GridSearchCV hyperparameter tuning on the best model")
    args = parser.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    print(f"Loading dataset from {args.data}...")
    X, y = load_dataset(args.data)
    print(f"Loaded {len(X)} rows, {X.shape[1]} features.")
    class_counts = y.value_counts().to_dict()
    print(f"Class balance: {class_counts} (1=phishing, 0=legitimate)")

    n_pos, n_neg = class_counts.get(1, 0), class_counts.get(0, 0)
    if n_pos and n_neg:
        ratio = max(n_pos, n_neg) / min(n_pos, n_neg)
        if ratio > 3:
            majority = "phishing" if n_pos > n_neg else "legitimate"
            print(f"\n  WARNING: classes are imbalanced ({ratio:.1f}:1, majority={majority}).")
            print(f"  class_weight='balanced' / scale_pos_weight below will compensate for")
            print(f"  training, but predictions will still be more reliable if you collect")
            print(f"  more {'legitimate' if majority == 'phishing' else 'phishing'} examples too.\n")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=RANDOM_STATE, stratify=y
    )
    print(f"Train: {len(X_train)} rows | Test: {len(X_test)} rows")

    # Scale features for distance-based models (SVM, Logistic Regression).
    # Tree-based models (RF, XGBoost, Decision Tree) don't need this, but
    # scaling doesn't hurt them either, so we apply it uniformly for
    # pipeline simplicity.
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    models = get_models(y_train=y_train)
    results = []
    trained_models = {}

    print("\n" + "=" * 70)
    print("TRAINING & EVALUATING BASELINE MODELS")
    print("=" * 70)

    for name, model in models.items():
        print(f"\nTraining {name}...")
        model.fit(X_train_scaled, y_train)
        metrics, cm, _ = evaluate_model(name, model, X_test_scaled, y_test)
        results.append(metrics)
        trained_models[name] = model
        print(f"  Accuracy={metrics['accuracy']:.4f}  Precision={metrics['precision']:.4f}  "
              f"Recall={metrics['recall']:.4f}  F1={metrics['f1']:.4f}"
              + (f"  ROC-AUC={metrics['roc_auc']:.4f}" if "roc_auc" in metrics else ""))
        print_confusion_matrix(cm, name)

    results_df = pd.DataFrame(results).sort_values("f1", ascending=False)
    print("\n" + "=" * 70)
    print("MODEL COMPARISON (sorted by F1 score)")
    print("=" * 70)
    print(results_df.to_string(index=False))

    best_name = results_df.iloc[0]["model"]
    best_model = trained_models[best_name]
    print(f"\nBest baseline model: {best_name}")

    # --- Optional hyperparameter tuning on the best model ---
    if args.tune:
        print(f"\n{'=' * 70}\nHYPERPARAMETER TUNING: {best_name}\n{'=' * 70}")
        param_grids = {
            "Random Forest": {
                "n_estimators": [100, 200, 400],
                "max_depth": [None, 10, 20],
                "min_samples_split": [2, 5],
            },
            "XGBoost": {
                "n_estimators": [100, 200, 400],
                "max_depth": [3, 6, 10],
                "learning_rate": [0.01, 0.1, 0.3],
            },
            "Decision Tree": {
                "max_depth": [5, 10, 20, None],
                "min_samples_split": [2, 5, 10],
            },
            "Logistic Regression": {
                "C": [0.01, 0.1, 1, 10],
                "penalty": ["l2"],
            },
            "SVM (RBF)": {
                "C": [0.1, 1, 10],
                "gamma": ["scale", "auto"],
            },
        }
        grid = param_grids.get(best_name)
        if grid:
            search = GridSearchCV(
                type(best_model)(**{k: v for k, v in best_model.get_params().items()
                                     if k not in grid}),
                grid, scoring="f1", cv=5, n_jobs=-1,
            )
            search.fit(X_train_scaled, y_train)
            print(f"Best params: {search.best_params_}")
            best_model = search.best_estimator_
            metrics, cm, _ = evaluate_model(f"{best_name} (tuned)", best_model, X_test_scaled, y_test)
            print(f"\nTuned performance: Accuracy={metrics['accuracy']:.4f}  F1={metrics['f1']:.4f}"
                  + (f"  ROC-AUC={metrics['roc_auc']:.4f}" if "roc_auc" in metrics else ""))
            print_confusion_matrix(cm, f"{best_name} (tuned)")
        else:
            print(f"No tuning grid defined for {best_name}, skipping tuning.")

    # --- Detailed classification report for the final chosen model ---
    y_pred_final = best_model.predict(X_test_scaled)
    print(f"\n{'=' * 70}\nFINAL CLASSIFICATION REPORT: {best_name}\n{'=' * 70}")
    print(classification_report(y_test, y_pred_final, target_names=["legitimate", "phishing"]))

    # --- Feature importance (tree-based models only) ---
    if hasattr(best_model, "feature_importances_"):
        importances = pd.Series(best_model.feature_importances_, index=X.columns)
        importances = importances.sort_values(ascending=False).head(15)
        print("\nTop 15 most important features:")
        print(importances.to_string())

    # --- Save artifacts ---
    model_path = os.path.join(args.out_dir, "best_model.joblib")
    scaler_path = os.path.join(args.out_dir, "scaler.joblib")
    columns_path = os.path.join(args.out_dir, "feature_columns.json")
    results_path = os.path.join(args.out_dir, "model_comparison.csv")

    joblib.dump(best_model, model_path)
    joblib.dump(scaler, scaler_path)
    with open(columns_path, "w") as f:
        json.dump(list(X.columns), f, indent=2)
    results_df.to_csv(results_path, index=False)

    print(f"\nSaved:")
    print(f"  Model              -> {model_path}")
    print(f"  Scaler             -> {scaler_path}")
    print(f"  Feature column list -> {columns_path}")
    print(f"  Comparison table   -> {results_path}")


if __name__ == "__main__":
    main()
