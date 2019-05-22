from passlib.hash import pbkdf2_sha512

if __name__ == "__main__":
    original_passwprd = "myPassword@12"
    encrypted_password = pbkdf2_sha512.hash(original_passwprd)
    print("Encrypted Password: " + encrypted_password)
    attempted_password_1 = "myPassword@12"
    matched1 = pbkdf2_sha512.verify(attempted_password_1, encrypted_password)
    print("\nPassword 1 matched: " + str(matched1))
    attempted_password_2 = "mypassword@12"
    matched2 = pbkdf2_sha512.verify(attempted_password_1, encrypted_password)
    print("\nPassword 1 matched: " + str(matched2))