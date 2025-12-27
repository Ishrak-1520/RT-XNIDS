import pandas as pd
import numpy as np
import joblib
import os
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# --- CONFIGURATION ---
GENERATE_DUMMY_MODE = False 

def train():
    print("[INFO] Initializing Deep Neural Network Training...")

    if GENERATE_DUMMY_MODE:
        print("[WARN] Using DUMMY data.")
        X = np.random.rand(1000, 79)
        y = np.random.choice(['Benign', 'DDoS', 'PortScan', 'Bot'], 1000)
    else:
        csv_path = "training_data.csv"
        
        if not os.path.exists(csv_path):
            possible_path = os.path.join("RT-XNIDS", "training_data.csv")
            if os.path.exists(possible_path):
                csv_path = possible_path
            else:
                print(f"[ERROR] Could not find 'training_data.csv'.")
                return

        print(f"[INFO] Loading real dataset from: {csv_path} ...")
        
        try:
            df = pd.read_csv(csv_path) 
            df.columns = df.columns.str.strip()
            
            # --- DATA CLEANING (THE FIX) ---
            print(f"[INFO] Raw Data Shape: {df.shape}")
            print("[INFO] Cleaning Infinite and NaN values...")
            
            # 1. Replace Infinity with NaN (Not a Number)
            df.replace([np.inf, -np.inf], np.nan, inplace=True)
            
            # 2. Drop all rows containing NaN
            df.dropna(inplace=True)
            
            print(f"[INFO] Cleaned Data Shape: {df.shape}")

            if df.empty:
                print("[ERROR] Dataset is empty after cleaning! Check your CSV.")
                return

            if 'Label' not in df.columns:
                print("[ERROR] 'Label' column not found.")
                return

            X = df.drop('Label', axis=1)
            y = df['Label']
            
        except Exception as e:
            print(f"[ERROR] Failed to process CSV: {e}")
            return

    # 1. Scale the Data
    print("[INFO] Scaling data...")
    scaler = MinMaxScaler()
    X_scaled = scaler.fit_transform(X)

    # 2. Split Data
    X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

    # 3. Define the Deep Neural Network (MLP)
    print("[INFO] Architecture: Deep Neural Network (Input -> 128 -> 64 -> Output)")
    model = MLPClassifier(
        hidden_layer_sizes=(128, 64), 
        activation='relu',
        solver='adam',
        max_iter=500,
        random_state=42,
        verbose=True
    )

    # 4. Train
    print("[INFO] Training Model (This may take a minute)...")
    model.fit(X_train, y_train)

    # 5. Evaluate
    print("[INFO] Evaluating...")
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"[SUCCESS] Training Complete. Accuracy: {acc*100:.2f}%")

    # 6. Save
    print("[INFO] Saving 'model.pkl' and 'scaler.pkl'...")
    joblib.dump(model, 'model.pkl')
    joblib.dump(scaler, 'scaler.pkl')
    print("[DONE] System ready.")

if __name__ == "__main__":
    train()