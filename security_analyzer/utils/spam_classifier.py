import os
import numpy as np
import pickle
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from django.conf import settings


class SpamDetector:
    """
    Handles text spam detection using scikit-learn models
    """
    def __init__(self, model_path=None, vectorizer_path=None):
        # Default model paths if not specified
        self.model_path = model_path or os.path.join(settings.BASE_DIR, 'ml_models', 'spam_model.joblib')
        self.vectorizer_path = vectorizer_path or os.path.join(settings.BASE_DIR, 'ml_models', 'tfidf_vectorizer.joblib')
        
        # Create ml_models directory if it doesn't exist
        os.makedirs(os.path.join(settings.BASE_DIR, 'ml_models'), exist_ok=True)
        
        # Load or create model
        self._load_or_create_model()
    def _load_or_create_model(self):
        """Load existing model or create a new one if not available"""
        try:
            # Try to load existing model
            if os.path.exists(self.model_path) and os.path.exists(self.vectorizer_path):
                self.model = joblib.load(self.model_path)
                self.vectorizer = joblib.load(self.vectorizer_path)
                print("Loaded existing spam classification model")
            else:
                # Create a simple model with some example data
                # In production, this should be trained on real data
                print("Creating new spam classification model")
                
                # Example training data
                X_train = [
                    "Buy viagra now", "Discount medications", "Win money fast", "Lottery winner",
                    "You've won millions", "Increase your size", "Free money", "Casino bonus",
                    "Earn money online", "Work from home", "Congratulations you won", "Claim your prize",
                    "Urgent business proposal", "Dear beneficiary", "Nigerian prince", "Inheritance claim",
                    "Enlarge your", "Free access", "Limited time offer", "Amazing opportunity"
                ]
                
                # Example spam labels
                y_train = [1] * len(X_train)  # All examples are spam (1)
                
                # Add some non-spam examples
                X_train.extend([
                    "Meeting tomorrow", "Please review document", "Project update", "Lunch today?",
                    "Family vacation photos", "Job application", "Conference registration", "Question about report",
                    "Weather forecast", "Traffic update", "Schedule change", "New employee introduction",
                    "Company newsletter", "Holiday schedule", "System maintenance", "Password reset",
                    "Invoice attached", "Thank you for your help", "Document review", "Team celebration"
                ])
                
                # Add non-spam labels
                y_train.extend([0] * 20)  # 20 non-spam examples (0)
                
                # Create and train the model
                self.vectorizer = TfidfVectorizer(max_features=1000)
                self.model = MultinomialNB()
                
                # Transform text data to feature vectors
                X_train_vec = self.vectorizer.fit_transform(X_train)
                
                # Train the model
                self.model.fit(X_train_vec, y_train)
                
                # Save the model and vectorizer
                joblib.dump(self.model, self.model_path)
                joblib.dump(self.vectorizer, self.vectorizer_path)
                print(f"Created and saved new spam classification model to {self.model_path}")
        
        except Exception as e:
            # Fallback to a simple pipeline if loading fails
            print(f"Error loading or creating model: {str(e)}")
            print("Creating fallback spam classification model")
            
            # Simple pipeline with a basic model
            self.pipeline = Pipeline([
                ('vectorizer', TfidfVectorizer(max_features=500)),
                ('classifier', MultinomialNB())
            ])
            
            # Simple training data
            X_train = [
                "Buy now", "Free money", "Discount", "Viagra", "Win", 
                "Hello", "Meeting", "Project", "Weather", "Family"
            ]
            y_train = [1, 1, 1, 1, 1, 0, 0, 0, 0, 0]  # First 5 are spam, last 5 are not
            
            # Train the model
            self.pipeline.fit(X_train, y_train)
            
            # Set model and vectorizer from pipeline components
            self.model = self.pipeline.named_steps['classifier']
            self.vectorizer = self.pipeline.named_steps['vectorizer']
    
    def predict(self, text):
        """Predict if text is spam"""
        try:
            # Transform text using the vectorizer
            text_vec = self.vectorizer.transform([text])
            
            # Get prediction and probability
            prediction = self.model.predict(text_vec)[0]
            probas = self.model.predict_proba(text_vec)[0]
            
            # Get confidence of prediction
            confidence = probas[1] if prediction == 1 else probas[0]
            
            return {
                'is_spam': bool(prediction),
                'confidence': float(confidence),
                'spam_score': float(probas[1]),
                'ham_score': float(probas[0])
            }
        
        except Exception as e:
            print(f"Error during prediction: {str(e)}")
            # Return default result on error
            return {
                'is_spam': False,
                'confidence': 0,
                'error': str(e)
            }
        
