from cryptography.fernet import Fernet
from CTkMessagebox import CTkMessagebox
import customtkinter as ctk
import json

# Placeholder for the encrypted password file
PASSWORD_FILE = "passwords.txt"
# Storing the key to make the key persistent across sessions
KEY_FILE = "encryption_key.key"

ctk.set_appearance_mode("System")  # Modes: system (default), light, dark
ctk.set_default_color_theme("green")  # Themes: blue (default), dark-blue, green

def generate_key():
    # Check if the key file exists
    try:
        with open(KEY_FILE, "rb") as key_file:
            key = key_file.read()
    except FileNotFoundError:
        # If the key file doesn't exist, generate a new key
        key = Fernet.generate_key()
        # Save the key to the file for future use
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
    
    return key

class Utility():

    def __init__(self, key):
        self.cipher_suite = Fernet(key)
  
    def encrypt_password(self,password):
        return self.cipher_suite.encrypt(password.encode())

    def decrypt_password(self,encrypted_password):
        #return cipher_suite.decrypt(encrypted_password).decode()
        try:
            return self.cipher_suite.decrypt(encrypted_password).decode()
        except:
            print("Invalid token. Password decryption failed.")
            return None

    def write_passwords_to_file(self,passwords):
        with open(PASSWORD_FILE, "w") as file:
            json.dump(passwords, file)

    def read_passwords_from_file(self):
        try:
            with open(PASSWORD_FILE, 'r') as file:
                return json.load(file)
        except (FileNotFoundError, json.JSONDecodeError):
            return {} 

    def add_password(self,name, passwd):
        # service = input("Enter the service/account name: ")
        # password = getpass.getpass("Enter the password: ")
        encrypted_password = self.encrypt_password(passwd)

        # Read existing passwords from the file
        passwords = self.read_passwords_from_file()

        # Add the new entry to the passwords dictionary
        passwords[name] = encrypted_password.decode()

        # Write the updated passwords back to the file
        self.write_passwords_to_file(passwords)

        print(f"Password for {name} added successfully.")

    def retrieve_password(self, name):

        # Read existing passwords from the file
        passwords = self.read_passwords_from_file()

        # for i in passwords:
        #     print(i)

        service = name

        if service in passwords:
            encrypted_password = passwords[service]
            decrypted_password = self.decrypt_password(encrypted_password)
            return decrypted_password
            # print(f"Password for {service}: {decrypted_password}")
        else:
            print(f"No password found for {service}.")

    def update_password(self, name, password):
        #service = input("Enter the service/account name: ")
        #password = getpass.getpass("Enter the new password: ")
        encrypted_password = self.encrypt_password(password)

        # Read existing passwords from the file
        passwords = self.read_passwords_from_file()

        if name in passwords:
            # Update the password for the service
            passwords[name] = encrypted_password.decode()

            # Write the updated passwords back to the file
            self.write_passwords_to_file(passwords)

            # print(f"Password for {name} updated successfully.")
            return True
        else:
            # print(f"No password found for {name}.")
            return False

    def delete_password(self, passName):
        
        # Read existing passwords from the file
        passwords = self.read_passwords_from_file()

        if passName in passwords:
            # Delete the password entry for the service
            del passwords[passName]

            # Write the updated passwords back to the file
            self.write_passwords_to_file(passwords)
            return True
            #print(f"Password for {passName} deleted successfully.")
        else:
            #print(f"No password found for {passName}.")
            return False

key = generate_key()
util = Utility(key)

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Password Manager")
        self.geometry("500x700") 
        self.minsize(500,600)

        self.mainFrame = MainFrame(self)
        self.appearance_mode_optionemenu = ctk.CTkOptionMenu(self, values=["Light", "Dark", "System"], command=self.change_appearance_mode_event).pack()
        #run app
        self.mainloop()

    def change_appearance_mode_event(self, new_appearance_mode: str):
            ctk.set_appearance_mode(new_appearance_mode)

class MainFrame(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent)

        ctk.CTkLabel(self, text="Passify", font=ctk.CTkFont(size=24, weight="bold")).pack(pady = 10)
        #ctk.CTkLabel(self, text="This is a Label",font=("Arial", 16), width=300).pack(padx = 20, pady = 20)
        
        self.tabView = TabView(self).pack(padx = 20, pady = 20)
        
        self.pack(padx = 30, pady = 30)

class TabView(ctk.CTkTabview):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)

        # create tabs
        self.add("Add Password")
        self.add("Display/Delete Passwords")
        self.add("Update Password")

        # add widgets on tabs 1
        self.uname = ctk.CTkEntry(self.tab("Add Password"), placeholder_text="Enter Account/Service Name")
        self.uname.pack(padx=20, pady=20)
        self.passwd = ctk.CTkEntry(self.tab("Add Password"), placeholder_text="Enter password", show="*")
        self.passwd.pack(padx=20)
        ctk.CTkButton(self.tab("Add Password"), text= "Save", command=self.get_entry).pack(pady = 20)

        #tab 2
        self.scroll_frame = ScrollableFrame(self.tab("Display/Delete Passwords"))
        self.scroll_frame.pack(pady = 20)
    
        self.retrieve_name = ctk.CTkEntry(self.tab("Display/Delete Passwords"), placeholder_text="Enter Account/Service Name")
        self.retrieve_name.pack(padx=20)

        self.button_frame = ctk.CTkFrame(self.tab("Display/Delete Passwords"))
        ctk.CTkButton(self.button_frame, text= "Show", command=self.get_pass).pack(side=ctk.LEFT, padx = 5)
        ctk.CTkButton(self.button_frame, text= "Delete", fg_color="red", command=self.delete_pass).pack(side=ctk.LEFT)
        #ctk.CTkButton(self.button_frame, text= "Refresh", command=self.refresh_passwords).pack(side=ctk.LEFT)
        self.button_frame.pack(pady = 10)

        self.display_label = ctk.CTkEntry(self.tab("Display/Delete Passwords"), placeholder_text="**Password**", state="disabled")
        self.display_label.pack(pady = 20)

        #tab 3
        self.update_name_entry = ctk.CTkEntry(self.tab("Update Password"), placeholder_text="Enter Account/Service Name")
        self.update_name_entry.pack(pady=10,padx=20)

        self.update_pass_entry = ctk.CTkEntry(self.tab("Update Password"), placeholder_text="Enter Updated Password", show="*")
        self.update_pass_entry.pack(pady=10,padx=20)

        ctk.CTkButton(self.tab("Update Password"), text= "Update", command=self.update_pass).pack(pady = 10)


    # Methods
    def refresh_passwords(self):
        self.scroll_frame.clear_frame()
    def get_entry(self):
        name = self.uname.get()
        pwd = self.passwd.get()

        if name == "":
            # Name is empty, display an error message or take appropriate action
            CTkMessagebox(title="Error", message="Service/User Name is required !", icon="cancel")
            return

        if pwd == "":
            # Password is empty, display an error message or take appropriate action
            CTkMessagebox(title="Error", message="Password is required !", icon="cancel")
            return

        # Validation passed, add the password and refresh the passwords
        util.add_password(name, pwd)
        CTkMessagebox(title="Success", message="Password stored successfully.",
                  icon="check", option_1="Ok")
        self.refresh_passwords()

        # Clear the input fields
        self.uname.delete(0, 'end')
        self.passwd.delete(0, 'end')

    def get_pass(self):
        retreive_name = self.retrieve_name.get()

        if retreive_name == "":
            # Name is empty, display an error message or take appropriate action
            CTkMessagebox(title="Error", message="Input Field is empty !", icon="info")
            return
        
        r_pass = util.retrieve_password(retreive_name)
        
        self.display_label.configure(state="normal")
        self.display_label.configure(placeholder_text=r_pass)

    def delete_pass(self):
        delete_name = self.retrieve_name.get()

        if delete_name == "":
            # Name is empty, display an error message or take appropriate action
            CTkMessagebox(title="Error", message="Input Field is empty !", icon="info")
            return

        confirmation = CTkMessagebox(title="Info", message="Note: This will delete the password!",
                  icon="warning", option_1="Ok", option_2="Cancel")
    
        if confirmation.get()=="Ok":
            deletion_status = util.delete_password(delete_name)
            if deletion_status:
                CTkMessagebox(title="Success", message="Password deleted successfully.",
                        icon="check", option_1="Ok")
            else:
                CTkMessagebox(title="Error", message="Password not found.",
                        icon="cancel", option_1="Ok")    
                
            # Clear the input fields
            self.retrieve_name.delete(0, 'end')
            self.display_label.configure(placeholder_text="")
        
            self.refresh_passwords()

        else:
            confirmation.destroy()
      
    def update_pass(self):
        upd_name = self.update_name_entry.get()
        upd_pass = self.update_pass_entry.get()

        if upd_name == "":
            # Name is empty, display an error message or take appropriate action
            CTkMessagebox(title="Error", message="Service/User Name is required !", icon="cancel")
            return

        if upd_pass == "":
            # Password is empty, display an error message or take appropriate action
            CTkMessagebox(title="Error", message="Password is required !", icon="cancel")
            return

        update_status = util.update_password(upd_name, upd_pass)
        if update_status:
            CTkMessagebox(title="Success", message="Password updated successfully.",
                        icon="check", option_1="Ok")
        else:
            CTkMessagebox(title="Error", message="Password not found.",
                        icon="cancel", option_1="Ok")    
                
        # Clear the input fields
        self.update_name_entry.delete(0, 'end')
        self.update_pass_entry.delete(0, 'end')
       
        self.refresh_passwords()
   
class ScrollableFrame(ctk.CTkScrollableFrame):
    def __init__(self, parent):
        super().__init__(parent)
        self.password_dict = util.read_passwords_from_file()
        self.populate_passwords()

    def populate_passwords(self):
        self.password_dict = util.read_passwords_from_file()

        for name in self.password_dict:
            ctk.CTkButton(self, text=name, fg_color="grey").pack(pady = 10)

    def clear_frame(self):
        #Destroys all old labels
        for widget in self.winfo_children():
            widget.destroy()

        self.populate_passwords()

if __name__ == "__main__":
    App()