import joblib

# Load trained ScamShield model
model = joblib.load("scamshield_model.pkl")

print("================================")
print("      SCAMSHIELD ML TESTER")
print("================================")

while True:
    message = input("\nEnter a message (or type 'exit'): ")

    if message.lower() == "exit":
        print("Exiting ScamShield...")
        break

    prediction = model.predict([message])[0]
    probabilities = model.predict_proba([message])[0]

    legitimate_probability = probabilities[0] * 100
    scam_probability = probabilities[1] * 100

    if prediction == 1:
        result = "SCAM"
    else:
        result = "LEGITIMATE"

    print("\n------------------------------")
    print(f"Prediction : {result}")
    print(f"Scam Risk  : {scam_probability:.2f}%")
    print(f"Safe Score : {legitimate_probability:.2f}%")
    print("------------------------------")