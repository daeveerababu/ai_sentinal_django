import os
import time
import joblib
import pandas as pd
from django.conf import settings
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.svm import LinearSVC
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from security_analyzer.models import SpamClassificationModel
from django.utils import timezone

# Directory setup
BASE_DIR = settings.BASE_DIR
ML_DIR = os.path.join(BASE_DIR, 'ml_models')
os.makedirs(ML_DIR, exist_ok=True)

# Dataset path
DATA_FILE = os.path.join(BASE_DIR, 'ml', 'data', 'spam.csv')

# Load and preprocess data
def load_data():
    df = pd.read_csv(DATA_FILE, encoding='latin-1')
    df = df.rename(columns={'v1': 'label', 'v2': 'text'})[['label', 'text']]
    df['label'] = df['label'].map(lambda x: 1 if x == 'spam' else 0)
    df.dropna(inplace=True)
    return df

# Train and register model
def train_model(model_type='nb'):
    df = load_data()
    X_train, X_test, y_train, y_test = train_test_split(
        df['text'], df['label'], test_size=0.2, stratify=df['label'], random_state=42
    )

    vectorizer = TfidfVectorizer(max_features=5000, stop_words='english')
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    if model_type == 'nb':
        clf = MultinomialNB()
    elif model_type == 'svm':
        base_clf = LinearSVC(random_state=42)
        clf = CalibratedClassifierCV(base_clf)
    elif model_type == 'rf':
        clf = RandomForestClassifier(n_estimators=100, random_state=42)
    else:
        raise ValueError("Unsupported model type")

    clf.fit(X_train_vec, y_train)
    y_pred = clf.predict(X_test_vec)

    metrics = {
        'accuracy': accuracy_score(y_test, y_pred),
        'precision': precision_score(y_test, y_pred),
        'recall': recall_score(y_test, y_pred),
        'f1_score': f1_score(y_test, y_pred)
    }

    # Save models
    model_file = os.path.join(ML_DIR, f'spam_model_{model_type}.joblib')
    vectorizer_file = os.path.join(ML_DIR, f'tfidf_vectorizer_{model_type}.joblib')
    joblib.dump(clf, model_file)
    joblib.dump(vectorizer, vectorizer_file)

    # Register to DB
    SpamClassificationModel.objects.update(is_active=False)
    SpamClassificationModel.objects.create(
        model_name=f"spam_{model_type}",
        model_version=timezone.now().strftime("%Y%m%d%H%M%S"),
        model_file=os.path.relpath(model_file, BASE_DIR),
        feature_extraction_file=os.path.relpath(vectorizer_file, BASE_DIR),
        accuracy=metrics['accuracy'],
        precision=metrics['precision'],
        recall=metrics['recall'],
        f1_score=metrics['f1_score'],
        is_active=True
    )

    print("Training complete and model registered.", metrics)
    return metrics

if __name__ == '__main__':
    train_model('nb')
