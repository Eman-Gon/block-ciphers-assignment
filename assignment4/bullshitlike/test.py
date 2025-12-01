# Test if it's actually a simple password
import bcrypt
durin_hash = b"$2b$13$6ypcazOOkUT/a7EwMuIjH.qbdqmHPDAC9B5c37RT9gEw18BX6FOay"
# Test a few quick ones
tests = ["Durin", "durin", "DURIN", "password", "123456"]
for pwd in tests:
    if bcrypt.checkpw(pwd.encode(), durin_hash):
        print(f"FOUND: {pwd}")
        break
else:
    print("None of the simple passwords worked")
