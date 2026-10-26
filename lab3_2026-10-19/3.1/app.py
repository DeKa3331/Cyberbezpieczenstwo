import jwt
import datetime

# Your secret key
SECRET_KEY = "mysecret"
ALGORITHM = "HS256"

# Payload data
payload = {
    "user_id": 1,
    "username": "student",
    "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
}

# Generate JWT
token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
print("JWT:", token)

# Decode the JWT to extract the payload (use the same secret key for decoding)
decoded_payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
print("Decoded Payload:", decoded_payload)
