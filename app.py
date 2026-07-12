import pandas as pd
import numpy as np

from sklearn.model_selection import TimeSeriesSplit
from sklearn.metrics import classification_report, roc_auc_score, accuracy_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline

try:
    from xgboost import XGBClassifier
    HAS_XGB = True
except Exception:
    HAS_XGB = False


def load_data(path):
    df = pd.read_csv(path)
    df.columns = [c.strip().lower() for c in df.columns]
    return df


def prepare_data(df):
    df = df.copy()

    rename_map = {
        "date": "date",
        "open": "open",
        "high": "high",
        "low": "low",
        "close": "close",
        "volume": "volume"
    }
    df = df.rename(columns=rename_map)

    needed = ["date", "open", "high", "low", "close", "volume"]
    missing = [c for c in needed if c not in df.columns]
    if missing:
        raise ValueError(f"Missing columns: {missing}")

    df["date"] = pd.to_datetime(df["date"])
    df = df.sort_values("date").reset_index(drop=True)

    df["return_1d"] = df["close"].pct_change()
    df["return_5d"] = df["close"].pct_change(5)
    df["vol_chg_1d"] = df["volume"].pct_change()
    df["vol_chg_5d"] = df["volume"].pct_change(5)

    for w in [5, 10, 20]:
        df[f"vol_ma_{w}"] = df["volume"].rolling(w).mean()
        df[f"vol_std_{w}"] = df["volume"].rolling(w).std()
        df[f"close_ma_{w}"] = df["close"].rolling(w).mean()
        df[f"close_std_{w}"] = df["close"].rolling(w).std()
        df[f"range_ma_{w}"] = (df["high"] - df["low"]).rolling(w).mean()

    df["volume_ratio_5"] = df["volume"] / df["vol_ma_5"]
    df["volume_ratio_20"] = df["volume"] / df["vol_ma_20"]
    df["price_range"] = df["high"] - df["low"]
    df["body"] = (df["close"] - df["open"]).abs()
    df["upper_wick"] = df["high"] - df[["open", "close"]].max(axis=1)
    df["lower_wick"] = df[["open", "close"]].min(axis=1) - df["low"]

    df["target"] = (df["close"].shift(-1) > df["close"]).astype(int)

    df = df.dropna().reset_index(drop=True)
    return df


def get_features(df):
    features = [
        "open", "high", "low", "close", "volume",
        "return_1d", "return_5d", "vol_chg_1d", "vol_chg_5d",
        "vol_ma_5", "vol_ma_10", "vol_ma_20",
        "vol_std_5", "vol_std_10", "vol_std_20",
        "close_ma_5", "close_ma_10", "close_ma_20",
        "close_std_5", "close_std_10", "close_std_20",
        "range_ma_5", "range_ma_10", "range_ma_20",
        "volume_ratio_5", "volume_ratio_20",
        "price_range", "body", "upper_wick", "lower_wick"
    ]
    features = [c for c in features if c in df.columns]
    return features


def build_model():
    if HAS_XGB:
        model = XGBClassifier(
            n_estimators=300,
            max_depth=4,
            learning_rate=0.05,
            subsample=0.8,
            colsample_bytree=0.8,
            reg_lambda=1.0,
            random_state=42,
            eval_metric="logloss"
        )
    else:
        model = RandomForestClassifier(
            n_estimators=300,
            max_depth=8,
            random_state=42,
            class_weight="balanced"
        )

    pipe = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("model", model)
    ])
    return pipe


def train_evaluate(df):
    features = get_features(df)
    X = df[features]
    y = df["target"]

    split_idx = int(len(df) * 0.8)
    X_train, X_test = X.iloc[:split_idx], X.iloc[split_idx:]
    y_train, y_test = y.iloc[:split_idx], y.iloc[split_idx:]

    model = build_model()
    model.fit(X_train, y_train)

    preds = model.predict(X_test)
    proba = None
    try:
        proba = model.predict_proba(X_test)[:, 1]
    except Exception:
        pass

    result = {
        "accuracy": accuracy_score(y_test, preds),
        "report": classification_report(y_test, preds, digits=4),
    }
    if proba is not None and len(np.unique(y_test)) > 1:
        result["roc_auc"] = roc_auc_score(y_test, proba)

    return model, features, result


def predict_next_day(model, features, df):
    last_row = df.iloc[[-1]][features]
    proba = model.predict_proba(last_row)[:, 1][0]
    pred = int(proba >= 0.5)
    return {"prediction": pred, "probability_up": float(proba)}


# ===== Example usage =====
# path = "egx_stock_data.csv"
# raw = load_data(path)
# data = prepare_data(raw)
# model, features, metrics = train_evaluate(data)
# print(metrics)
# print(predict_next_day(model, features, data))
