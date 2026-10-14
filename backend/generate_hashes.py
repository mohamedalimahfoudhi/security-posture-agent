from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

users = [
    ("admin@example.com", "Admin123!"),
    ("analyst@example.com", "Analyst123!"),
    ("viewer@example.com", "Viewer123!")
]

for email, pwd in users:
    print(f"'{email}': '{pwd_context.hash(pwd)}'")
