import os
import joblib
import pandas as pd
from django.conf import settings
from django.utils import timezone
# Adjusted import to reference the correct models module
from security_analyzer.models import SpamClassificationModel

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.svm import LinearSVC
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score


class SpamDetector:

    """
    Comprehensive spam detector leveraging scikit-learn.
    Supports Naive Bayes, SVM, and RandomForest classifiers.
    Models and vectorizers are versioned and registered via SpamClassificationModel.
    """

    def __init__(self, model_type='nb', retrain=False, data_path=None):
        """
        Initialize detector; train or load model based on parameters.

        :param model_type: 'nb', 'svm', or 'rf'
        :param retrain: force retraining even if model exists
        :param data_path: optional CSV path with 'text','label' columns
        """
        # Set up directories
        self.base_dir = settings.BASE_DIR
        self.ml_dir = os.path.join(self.base_dir, 'ml_models')
        os.makedirs(self.ml_dir, exist_ok=True)

        # Define file paths
        self.model_type = model_type
        self.model_file = os.path.join(self.ml_dir, f'spam_model_{model_type}.joblib')
        self.vectorizer_file = os.path.join(self.ml_dir, f'tfidf_vectorizer_{model_type}.joblib')

        # Load or train
        if retrain or not (os.path.exists(self.model_file) and os.path.exists(self.vectorizer_file)):
            self.train_model(data_path)
        else:
            self._load_model()

    def _load_model(self):
        """Load vectorizer and classifier from disk."""
        self.vectorizer = joblib.load(self.vectorizer_file)
        self.model = joblib.load(self.model_file)

    def train_model(self, data_path=None, test_size=0.2, random_state=42):
        """
        Train and persist a new model. Dataset can be provided or defaults used.

        :returns: dict of training metrics
        """
        # Load data
        if data_path and os.path.exists(data_path):
            df = pd.read_csv(data_path)
            texts = df['text'].astype(str).tolist()
            labels = df['label'].astype(int).tolist()
        else:
            # Placeholder data; replace with real dataset
            texts = [
                # Spam samples
                "Win money now!", "Limited time offer", "Earn cash fast", 
                "Free entry to win", "Claim your prize", "Cheap meds online",
                # Ham samples
                "Meeting at 10am", "Please review the attached report", "Lunch tomorrow?",
                "Happy birthday!", "Project update attached", "See you at the conference"
            ]
            labels = [1,1,1,1,1,1, 0,0,0,0,0,0]

        # Split dataset
        X_train, X_test, y_train, y_test = train_test_split(
            texts, labels, test_size=test_size, random_state=random_state
        )

        # Vectorize text data
        self.vectorizer = TfidfVectorizer(
            max_features=5000,
            stop_words='english'
        )
        X_train_vec = self.vectorizer.fit_transform(X_train)

        # Choose classifier
        if self.model_type == 'nb':
            clf = MultinomialNB()
        elif self.model_type == 'svm':
            base_clf = LinearSVC(random_state=random_state, max_iter=10000)
            clf = CalibratedClassifierCV(base_clf)
        elif self.model_type == 'rf':
            clf = RandomForestClassifier(
                n_estimators=100, random_state=random_state, n_jobs=-1
            )
        else:
            raise ValueError(f"Unsupported model_type '{self.model_type}'")

        # Train model
        self.model = clf.fit(X_train_vec, y_train)

        # Evaluate on test set
        X_test_vec = self.vectorizer.transform(X_test)
        y_pred = self.model.predict(X_test_vec)
        metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred),
            'recall': recall_score(y_test, y_pred),
            'f1_score': f1_score(y_test, y_pred),
        }

        # Save vectorizer and model
        joblib.dump(self.vectorizer, self.vectorizer_file)
        joblib.dump(self.model, self.model_file)

        # Register model in DB
        SpamClassificationModel.objects.update(is_active=False)
        SpamClassificationModel.objects.create(
            model_name=f"spam_{self.model_type}",
            model_version=timezone.now().strftime("%Y%m%d%H%M%S"),
            model_file=os.path.relpath(self.model_file, self.base_dir),
            feature_extraction_file=os.path.relpath(self.vectorizer_file, self.base_dir),
            accuracy=metrics['accuracy'],
            precision=metrics['precision'],
            recall=metrics['recall'],
            f1_score=metrics['f1_score'],
            is_active=True,
        )
        return metrics

    def predict(self, text: str) -> dict:
        """
        Predict spam/ham and return probabilities.

        :param text: raw email or message body
        :returns: dict with keys 'is_spam','confidence','spam_score','ham_score'
        """
        if not hasattr(self, 'model') or not hasattr(self, 'vectorizer'):
            self._load_model()

        vec = self.vectorizer.transform([text])
        pred = self.model.predict(vec)[0]

        # Handle classifiers without predict_proba
        if hasattr(self.model, 'predict_proba'):
            probas = self.model.predict_proba(vec)[0]
            confidence = float(probas[pred])
            spam_score = float(probas[1])
            ham_score = float(probas[0])
        else:
            # Use decision function if available
            if hasattr(self.model, 'decision_function'):
                score = self.model.decision_function(vec)[0]
                confidence = abs(float(score))
                spam_score = float(score) if score > 0 else 0.0
                ham_score = 1.0 - spam_score
            else:
                confidence = 0.0
                spam_score = 1.0 if pred == 1 else 0.0
                ham_score = 1.0 - spam_score

        return {
            'is_spam': bool(pred),
            'confidence': confidence,
            'spam_score': spam_score,
            'ham_score': ham_score,
        }

    def list_models(self) -> list:
        """
        List all registered models with metadata.
        """
        qs = SpamClassificationModel.objects.order_by('-created_at')
        return [
            {
                'name': m.model_name,
                'version': m.model_version,
                'accuracy': m.accuracy,
                'precision': m.precision,
                'recall': m.recall,
                'f1_score': m.f1_score,
                'active': m.is_active,
                'created': m.created_at,
            }
            for m in qs
        ]

    def deactivate_all(self):
        """
        Deactivate all existing models in the DB.
        """
        SpamClassificationModel.objects.filter(is_active=True).update(is_active=False)

    def cleanup(self, keep_latest=3):
        """
        Remove old model files, keeping only the latest N.
        """
        all_models = SpamClassificationModel.objects.order_by('-created_at')
        for m in all_models[keep_latest:]:
            for path in [m.model_file, m.feature_extraction_file]:
                try:
                    abs_path = os.path.join(self.base_dir, path)
                    os.remove(abs_path)
                except Exception:
                    pass
            m.delete()
