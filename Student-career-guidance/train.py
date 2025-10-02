import os
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, OneHotEncoder, LabelEncoder
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.metrics import accuracy_score

# -------------------
# Config
# -------------------
DATAFILE = "Career_Predict.csv"      # dataset file
TARGET_COLUMN = "Career_Goals"       # target column
MODEL_DIR = "model"                  # Save model as directory
os.makedirs(MODEL_DIR, exist_ok=True)
model_path = os.path.join(MODEL_DIR, "model")  # ✅ directory for model
le_path = os.path.join(MODEL_DIR, "label_encoder.pkl")  # label encoder file

# -------------------
# Train and Save Model
# -------------------
def train_and_save_model():
    print("📂 Loading dataset...")
    df = pd.read_csv(DATAFILE)

    if TARGET_COLUMN not in df.columns:
        raise ValueError(f"Target column '{TARGET_COLUMN}' not found in dataset!")

    # Encode target column
    le = LabelEncoder()
    df[TARGET_COLUMN] = le.fit_transform(df[TARGET_COLUMN])

    X = df.drop(TARGET_COLUMN, axis=1)
    y = df[TARGET_COLUMN]

    # Detect categorical and numeric columns
    cat_cols = X.select_dtypes(include=["object"]).columns.tolist()
    num_cols = X.select_dtypes(include=[np.number]).columns.tolist()

    print(f"Numeric columns: {num_cols}")
    print(f"Categorical columns: {cat_cols}")

    # Pipelines for preprocessing
    num_pipeline = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", StandardScaler())
    ])

    cat_pipeline = Pipeline([
        ("imputer", SimpleImputer(strategy="most_frequent")),
        ("encoder", OneHotEncoder(handle_unknown="ignore", sparse_output=False))
    ])

    preprocessor = ColumnTransformer([
        ("num", num_pipeline, num_cols),
        ("cat", cat_pipeline, cat_cols)
    ])

    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # -------------------
    # Logistic Regression
    # -------------------
    print("⚡ Training Logistic Regression...")
    log_reg = Pipeline([
        ("pre", preprocessor),
        ("clf", LogisticRegression(max_iter=300, solver="liblinear"))
    ])

    log_reg.fit(X_train, y_train)
    y_pred = log_reg.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"🔹 Logistic Regression Accuracy: {acc:.2f}")

    # Fallback to RandomForest if accuracy < 0.6
    if acc < 0.6:
        print("⚠️ Accuracy below 0.6 → Switching to RandomForest...")
        rf = Pipeline([
            ("pre", preprocessor),
            ("clf", RandomForestClassifier(
                n_estimators=50,
                max_depth=15,
                random_state=42,
                n_jobs=-1
            ))
        ])
        rf.fit(X_train, y_train)
        y_pred = rf.predict(X_test)
        acc = accuracy_score(y_test, y_pred)
        model = rf
        print(f"🔹 RandomForest Accuracy: {acc:.2f}")
    else:
        model = log_reg

    # Save model as directory + label encoder
    joblib.dump(model, model_path, compress=3)  # creates model/ directory
    joblib.dump(le, le_path)
    print(f"✅ Model saved in directory '{MODEL_DIR}/', Accuracy = {acc:.2f}")


# -------------------
# Load Model
# -------------------
def load_model():
    if not os.path.exists(model_path) or not os.path.exists(le_path):
        print("⚠️ Model or encoder not found → Training new model...")
        train_and_save_model()
    model = joblib.load(model_path)
    le = joblib.load(le_path)
    return model, le


# -------------------
# Main
# -------------------
if __name__ == "__main__":
    model, le = load_model()
    print("🎯 Model + LabelEncoder loaded successfully!")
