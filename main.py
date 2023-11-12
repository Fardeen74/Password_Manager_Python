from cryptography.fernet import Fernet
import getpass
import json

# Generate a key for encryption (keep it secure, maybe store it separately)
KEY = Fernet.generate_key()

#The cipher_suite is an instance of Fernet initialized with a randomly generated key (Fernet.generate_key()).
cipher_suite = Fernet(KEY)

# Placeholder for the encrypted password file
PASSWORD_FILE = "passwords.txt"

def display_menu():
    print("Password Manager Menu:")
    print("1. Add a new password")
    print("2. Retrieve a password")
    print("3. Update a password")
    print("4. Delete a password")
    print("5. Exit")

def get_user_choice():
    return input("Enter your choice (1-5): ")

def encrypt_password(password):
    return cipher_suite.encrypt(password.encode())

def decrypt_password(encrypted_password):
    return cipher_suite.decrypt(encrypted_password).decode()

def write_passwords_to_file(passwords):
    with open(PASSWORD_FILE, "w") as file:
        json.dump(passwords, file)

def read_passwords_from_file():
    try:
        with open(PASSWORD_FILE, 'r') as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return {} 


def add_password():
    service = input("Enter the service/account name: ")
    password = getpass.getpass("Enter the password: ")
    encrypted_password = encrypt_password(password)

    # Read existing passwords from the file
    passwords = read_passwords_from_file()

    # Add the new entry to the passwords dictionary
    passwords[service] = encrypted_password.decode()

    # Write the updated passwords back to the file
    write_passwords_to_file(passwords)

    print(f"Password for {service} added successfully.")

def retrieve_password():
    service = input("Enter the service/account name: ")

    # Read existing passwords from the file
    passwords = read_passwords_from_file()

    if service in passwords:
        encrypted_password = passwords[service]
        decrypted_password = decrypt_password(encrypted_password)
        print(f"Password for {service}: {decrypted_password}")
    else:
        print(f"No password found for {service}.")

def update_password():
    service = input("Enter the service/account name: ")
    password = getpass.getpass("Enter the new password: ")
    encrypted_password = encrypt_password(password)

    # Read existing passwords from the file
    passwords = read_passwords_from_file()

    if service in passwords:
        # Update the password for the service
        passwords[service] = encrypted_password.decode()

        # Write the updated passwords back to the file
        write_passwords_to_file(passwords)

        print(f"Password for {service} updated successfully.")
    else:
        print(f"No password found for {service}.")

def delete_password():
    service = input("Enter the service/account name: ")

    # Read existing passwords from the file
    passwords = read_passwords_from_file()

    if service in passwords:
        # Delete the password entry for the service
        del passwords[service]

        # Write the updated passwords back to the file
        write_passwords_to_file(passwords)

        print(f"Password for {service} deleted successfully.")
    else:
        print(f"No password found for {service}.")

def main():
    while True:
        display_menu()
        choice = get_user_choice()

        if choice == '1':
            add_password()
        elif choice == '2':
            retrieve_password()
        elif choice == '3':
            update_password()
        elif choice == '4':
            delete_password()
        elif choice == '5':
            print("Exiting the Password Manager. Goodbye!")
            break
        else:
            print("Invalid choice. Please enter a number between 1 and 5.")

if __name__ == "__main__":
    main()