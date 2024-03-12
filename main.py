import tkinter as tk
from tkinter import ttk, filedialog
from tkinter.messagebox import showinfo, showerror
from tkinter import ttk
from tkinter import messagebox
import sqlite3
from datetime import datetime, timedelta
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
from Crypto.PublicKey import RSA, DSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64

class InitialApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Welcome Page ! Louay Crypt App")
        self.master.geometry("400x350")
        self.master.iconbitmap("louay.ico")
        self.font_style = ("Helvetica", 12)

        self.create_initial_page()

        self.timer_canvas = tk.Canvas(self.master, width=100, height=100, bg='white')
        self.timer_canvas.pack(pady=10)
        self.timer_value = 0
        self.timer_running = False
        self.choice_made = False

        self.start_timer()

    def start_timer(self):
        self.timer_running = True
        self.draw_timer()

    def draw_timer(self):
        self.timer_canvas.delete("all")

        x0, y0, x1, y1 = 10, 10, 90, 90
        self.timer_canvas.create_arc(x0, y0, x1, y1, start=90, extent=self.timer_value * 360 / 5, style=tk.ARC,
                                     outline="green", width=2)

        self.timer_canvas.create_text(50, 50, text=str(self.timer_value), font=("Helvetica", 16), fill="black")

        if self.timer_value < 5 and not self.choice_made:
            self.timer_value += 1
            self.master.after(1000, self.draw_timer)
        else:
            self.timer_running = False
            if not self.choice_made:
                messagebox.showinfo("Time's Up", "You were inactive for 5 seconds to choose. The application will be closed....")
                self.master.destroy()
    def create_initial_page(self):
        self.login_button = tk.Button(self.master, text="Login", command=self.show_login_page,
                                      relief=tk.RAISED, bg="green", fg="white", font=self.font_style)
        self.login_button.pack(pady=10)

        self.register_button = tk.Button(self.master, text="Register", command=self.show_registration_page,
                                         relief=tk.RAISED, bg="blue", fg="white", font=self.font_style)
        self.register_button.pack(pady=10)


    def create_initial_page(self):
        self.login_button = tk.Button(self.master, text="Login", command=self.show_login_page,
                                      relief=tk.RAISED, bg="green", fg="white", font=self.font_style)
        self.login_button.pack(pady=10)

        self.register_button = tk.Button(self.master, text="Register", command=self.show_registration_page,
                                         relief=tk.RAISED, bg="blue", fg="white", font=self.font_style)
        self.register_button.pack(pady=10)

    def show_login_page(self):
        self.master.destroy()
        login_window = tk.Tk()
        login_app = EncryptionApp(login_window)
        login_window.mainloop()

    def show_registration_page(self):
        self.master.destroy()
        registration_window = tk.Tk()
        registration_app = RegistrationApp(registration_window)
        registration_window.mainloop()

class RegistrationApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Registration Page")
        self.master.geometry("400x350")
        self.master.iconbitmap("louay.ico")
        self.font_style = ("Helvetica", 12)

        self.create_registration_page()

    def create_registration_page(self):
        self.username_label = tk.Label(self.master, text="Username:", font=self.font_style, padx=10, pady=5)
        self.username_label.pack()

        self.username_entry = tk.Entry(self.master, font=self.font_style)
        self.username_entry.pack(padx=10, pady=5)

        self.password_label = tk.Label(self.master, text="Password:", font=self.font_style, padx=10, pady=5)
        self.password_label.pack()

        self.password_entry = tk.Entry(self.master, show="*", font=self.font_style)
        self.password_entry.pack(padx=10, pady=5)

        self.register_button = tk.Button(self.master, text="Register", command=self.register_user, relief=tk.RAISED,
                                         bg="orange", fg="white", font=self.font_style)
        self.register_button.pack(pady=10)

        self.cancel_button = tk.Button(self.master, text="Cancel", command=self.cancel_registration, relief=tk.RAISED,
                                       bg="gray", fg="white", font=self.font_style)
        self.cancel_button.pack(pady=10)

    def register_user(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        try:
            connection = sqlite3.connect("user_credentials.db")
            cursor = connection.cursor()
            cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
            connection.commit()
            connection.close()
            showinfo("Registration Successful", "User registered successfully!")

            self.master.destroy()

            root = tk.Tk()
            initial_app = InitialApp(root)
            root.mainloop()

        except Exception as e:
            showerror("Registration Error", f"An error occurred during registration: {str(e)}")

    def cancel_registration(self):
        self.master.destroy()
class EncryptionApp:
    def __init__(self, master):
        print("Initializing EncryptionApp")
        self.master = master
        self.master.title("Login Page")
        self.master.geometry("400x350")
        self.master.iconbitmap("louay.ico")
        self.font_style = ("Helvetica", 12)

        self.connection = sqlite3.connect("user_credentials.db")
        self.create_tables_if_not_exist()
        self.admin_connection = sqlite3.connect("admin_credentials.db")
        self.create_admin_table_if_not_exists()
        self.keys_connection = sqlite3.connect("encryption_app.db")
        self.create_keys_table_if_not_exists()
        self.create_login_page()

        self.set_style()

    def set_style(self):
        style = ttk.Style()
        style.theme_use("clam")



    def create_tables_if_not_exist(self):
        cursor = self.connection.cursor()
        cursor.execute('''
                 CREATE TABLE IF NOT EXISTS users (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     username TEXT UNIQUE NOT NULL,
                     password TEXT NOT NULL,
                     login_attempts INTEGER DEFAULT 0,
                     last_failed_attempt TIMESTAMP,
                     locked_until TIMESTAMP
                 )
             ''')
        self.connection.commit()

        cursor.execute('''
                 CREATE TABLE IF NOT EXISTS keys (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     algorithm TEXT NOT NULL,
                     key_path TEXT NOT NULL,
                     key_content TEXT NOT NULL,
                     key_length INTEGER,
                     creation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                 )
             ''')
        self.connection.commit()


    def create_admin_table_if_not_exists(self):
        admin_cursor = self.admin_connection.cursor()
        admin_cursor.execute('''
            CREATE TABLE IF NOT EXISTS admin (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        self.admin_connection.commit()

    def create_keys_table_if_not_exists(self):
        cursor = self.keys_connection.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                algorithm TEXT NOT NULL,
                key_path TEXT NOT NULL,
                key_content TEXT NOT NULL,
                key_length INTEGER NOT NULL,
                signature_path TEXT 
            )
        ''')
        self.keys_connection.commit()

    def update_keys_info(self, algorithm, key_path, key_content):
        cursor = self.keys_connection.cursor()
        cursor.execute('''
            INSERT INTO keys (algorithm, key_path, key_content, key_length)
            VALUES (?, ?, ?, ?)
        ''', (algorithm, key_path, key_content, len(key_content)))
        self.keys_connection.commit()

    def create_login_page(self):
        self.username_label = tk.Label(self.master, text="Username:", font=self.font_style, padx=10, pady=5)
        self.username_label.pack()

        self.username_entry = tk.Entry(self.master, font=self.font_style)
        self.username_entry.pack(padx=10, pady=5)

        self.password_label = tk.Label(self.master, text="Password:", font=self.font_style, padx=10, pady=5)
        self.password_label.pack()

        self.password_entry = tk.Entry(self.master, show="*", font=self.font_style)
        self.password_entry.pack(padx=10, pady=5)

        self.login_button = tk.Button(self.master, text="Login", command=self.authenticate, relief=tk.RAISED,
                                      bg="green", fg="white", font=self.font_style)
        self.login_button.pack(pady=10)

        self.show_ban_time_button = tk.Button(self.master, text="Show Ban Time", command=self.show_ban_time,
                                              relief=tk.RAISED, bg="red", fg="white", font=self.font_style)
        self.show_ban_time_button.pack(pady=10)

        self.admin_button = tk.Button(self.master, text="Admin", command=self.show_admin_interface_with_password,
                                      relief=tk.RAISED, bg="blue", fg="white", font=self.font_style)
        self.admin_button.pack(pady=10)
    def show_admin_interface_with_password(self):
        admin_password_dialog = tk.Toplevel(self.master)
        admin_password_dialog.title("Admin Password")
        admin_password_dialog.geometry("300x150")
        self.master.iconbitmap("louay.ico")

        password_label = tk.Label(admin_password_dialog, text="Enter Admin Password:")
        password_label.pack()

        password_entry = tk.Entry(admin_password_dialog, show="*")
        password_entry.pack()

        submit_button = tk.Button(admin_password_dialog, text="Submit",
                                  command=lambda: self.authenticate_and_show_admin(password_entry.get(),
                                                                                   admin_password_dialog))
        submit_button.pack()

    def authenticate_and_show_admin(self, entered_password, admin_password_dialog):
        if self.authenticate_admin(entered_password):
            admin_password_dialog.destroy()
            self.show_admin_interface(authenticated=True)
        else:
            messagebox.showerror("Authentication Failed", "Incorrect admin password. Please try again.")

    def authenticate_admin(self, entered_password):
        admin_cursor = self.admin_connection.cursor()
        admin_cursor.execute('SELECT password FROM admin WHERE username=?', ('adminlouay',))
        admin_password = admin_cursor.fetchone()

        if admin_password and entered_password == admin_password[0]:
            return True
        else:
            return False

    def show_admin_interface(self, authenticated=False):
        if authenticated:
            admin_window = tk.Toplevel(self.master)
            admin_window.title("Admin Interface")
            admin_window.geometry("800x600")
            self.master.iconbitmap("louay.ico")

            columns = ("Username", "Password", "Login Attempts", "Last Failed Attempt")
            user_tree = ttk.Treeview(admin_window, columns=columns, show="headings", selectmode="browse")

            for col in columns:
                user_tree.heading(col, text=col)
                user_tree.column(col, anchor="center")

            self.populate_treeview(user_tree)

            user_tree.pack(expand=True, fill="both")

            def reset_ban():
                selected_item = user_tree.selection()
                if selected_item:
                    username = user_tree.item(selected_item, "values")[0]
                    self.reset_ban_for_user(username)
                    showinfo("Ban Reset", f"The ban for user {username} has been reset.")
                    user_tree.delete(selected_item)
                else:
                    showinfo("No User Selected", "Please select a user to reset the ban.")

            reset_ban_button = tk.Button(admin_window, text="Delete Logs", command=reset_ban)
            reset_ban_button.pack()

            refresh_button = tk.Button(admin_window, text="Refresh", command=lambda: self.refresh_treeview(user_tree))
            refresh_button.pack()

            admin_window.mainloop()

    def refresh_treeview(self, tree):
        tree.delete(*tree.get_children())

        self.populate_treeview(tree)

    def reset_ban_for_user(self, username):
        cursor = self.connection.cursor()
        cursor.execute(
            'UPDATE users SET login_attempts = 0, last_failed_attempt = NULL, locked_until = NULL WHERE username=?',
            (username,))
        self.connection.commit()

    def is_account_locked(self, username, last_attempt_str=None, locked_until_str=None):
        print(f"Checking if account is locked for {username}")

        if last_attempt_str:
            last_attempt_datetime = datetime.strptime(last_attempt_str, "%Y-%m-%dT%H:%M:%S.%f")
            if datetime.now() - last_attempt_datetime < timedelta(minutes=5):
                print(f"Account is locked for {username}")
                return True

        cursor = self.connection.cursor()
        cursor.execute('SELECT login_attempts, last_failed_attempt, locked_until FROM users WHERE username=?',
                       (username,))
        result = cursor.fetchone()

        if result:
            login_attempts, last_attempt_str, locked_until_str = result
            print(f"Login Attempts: {login_attempts}")
            print(f"Last Failed Attempt: {last_attempt_str}")
            print(f"Locked Until: {locked_until_str}")

            if login_attempts >= 3 and datetime.now() - datetime.strptime(last_attempt_str,
                                                                          "%Y-%m-%dT%H:%M:%S.%f") < timedelta(
                minutes=5):
                if locked_until_str and datetime.now() < datetime.strptime(locked_until_str, "%Y-%m-%dT%H:%M:%S.%f"):
                    print(f"Account is locked until {locked_until_str} for {username}")
                    return True

        print(f"Account is not locked for {username}")
        return False

    def show_ban_time(self):
        username = self.username_entry.get()
        cursor = self.connection.cursor()
        cursor.execute('SELECT login_attempts, last_failed_attempt FROM users WHERE username=?', (username,))
        result = cursor.fetchone()

        if result:
            login_attempts, last_attempt_str = result
            if login_attempts >= 3 and datetime.now() - datetime.strptime(last_attempt_str,
                                                                          "%Y-%m-%dT%H:%M:%S.%f") < timedelta(
                    minutes=5):
                remaining_time = timedelta(minutes=5) - (
                            datetime.now() - datetime.strptime(last_attempt_str, "%Y-%m-%dT%H:%M:%S.%f"))
                showinfo("Ban Time Left", f"Remaining ban time for {username}: {remaining_time}")
            else:
                showinfo("No Ban", f"{username} is not currently banned.")

    def authenticate(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if self.check_credentials(username, password):
            self.reset_login_attempts(username)
            self.show_main_interface()
        else:
            if not self.check_username_exist(username):
                showerror("Authentication Failed", "Invalid username")
            else:
                if self.is_account_locked(username):
                    showinfo("Account Locked", f"{username} is banned. Try again later.")
                else:
                    self.increment_login_attempts(username)
                    showerror("Authentication Failed", "Incorrect password.\nHint: nids")

    def check_credentials(self, username, password):
        print(f"Checking credentials for {username}")

        cursor = self.connection.cursor()
        cursor.execute('SELECT password, login_attempts, last_failed_attempt FROM users WHERE username=?', (username,))
        result = cursor.fetchone()

        if result:
            stored_password, login_attempts, last_failed_attempt = result
            print(f"Stored Password: {stored_password}")
            print(f"Entered Password: {password}")

            if login_attempts >= 3 and self.is_account_locked(username, last_failed_attempt):
                return False

            if stored_password == password:
                return True

        return False

    def check_username_exist(self, username):
        cursor = self.connection.cursor()
        cursor.execute('SELECT * FROM users WHERE username=?', (username,))
        return cursor.fetchone() is not None

    def increment_login_attempts(self, username):
        cursor = self.connection.cursor()
        cursor.execute('SELECT login_attempts, last_failed_attempt FROM users WHERE username=?', (username,))
        result = cursor.fetchone()

        if result:
            login_attempts, last_attempt_str = result
            print(f"Before incrementing login attempts for {username}: {login_attempts}")

            cursor.execute(
                'UPDATE users SET login_attempts = login_attempts + 1, last_failed_attempt = ? WHERE username=?',
                (datetime.now().isoformat(), username))

            if login_attempts + 1 >= 3:
                locked_until = (datetime.now() + timedelta(minutes=5)).isoformat()
                cursor.execute('UPDATE users SET locked_until = ? WHERE username=?', (locked_until, username))

            self.connection.commit()

            cursor.execute('SELECT login_attempts, last_failed_attempt, locked_until FROM users WHERE username=?',
                           (username,))
            result = cursor.fetchone()
            print(f"After incrementing login attempts for {username}: {result}")

    def reset_login_attempts(self, username):
        cursor = self.connection.cursor()
        cursor.execute(
            'UPDATE users SET login_attempts = 0, last_failed_attempt = NULL, locked_until = NULL WHERE username=?',
            (username,))
        self.connection.commit()

    def show_main_interface(self):
        self.master.destroy()

        root = tk.Tk()
        app = EncryptionAppMain(root)
        root.mainloop()

    def populate_treeview(self, tree):
        cursor = self.connection.cursor()
        cursor.execute('SELECT username, password, login_attempts, last_failed_attempt FROM users')
        user_data = cursor.fetchall()

        for user_info in user_data:
            tree.insert("", tk.END, values=user_info)

class EncryptionAppMain:
    def __init__(self, master):
        print("Initializing EncryptionAppMain")
        self.master = master
        self.master.title("Encryption App")
        self.master.geometry("1000x700")
        self.keys_connection = sqlite3.connect("encryption_app.db")
        self.master.iconbitmap("louay.ico")

        self.background_image = tk.PhotoImage(file="background_image.png")
        self.background_label = tk.Label(self.master, image=self.background_image)
        self.background_label.place(x=0, y=0, relwidth=1, relheight=1)

        self.developed_by_label = tk.Label(self.master, text="Developer: Louay Abidi", font=("Helvetica", 12))
        self.developed_by_label.pack(pady=10)

        self.encrypt_button = tk.Button(self.master, text="Encrypt", command=self.encrypt_interface, font=("Helvetica", 14))
        self.encrypt_button.pack(pady=20)

        self.decrypt_button = tk.Button(self.master, text="Decrypt", command=self.decrypt_interface, font=("Helvetica", 14))
        self.decrypt_button.pack(pady=20)

        self.keys_button = tk.Button(self.master, text="View Keys", command=self.show_keys_interface, font=("Helvetica", 14))
        self.keys_button.pack(pady=20)

        self.keys_info = []


    def generate_aes_key(self):
        return get_random_bytes(16)

    def generate_rsa_keypair(self):
        key = RSA.generate(2048)
        private_key = key.export_key().decode('utf-8')
        public_key = key.publickey().export_key().decode('utf-8')
        return private_key, public_key

    def encrypt_aes(self, data, key):
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return ciphertext, cipher.nonce, tag

    def decrypt_aes(self, ciphertext, key, nonce, tag):
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)
        return data

    def encrypt_rsa(self, data, public_key):
        recipient_key = RSA.import_key(public_key)
        cipher = PKCS1_OAEP.new(recipient_key)
        ciphertext = cipher.encrypt(data)
        return ciphertext

    def decrypt_rsa(self, ciphertext, private_key):
        key = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(key)
        data = cipher.decrypt(ciphertext)
        return data

    def generate_dsa_keypair(self):
        key = DSA.generate(2048)
        private_key = key.export_key().decode('utf-8')
        public_key = key.publickey().export_key().decode('utf-8')
        return private_key, public_key


    def sign_data_with_dsa(self, data, private_key):
        key = DSA.import_key(private_key)
        h = SHA256.new(data)
        signer = DSS.new(key, 'fips-186-3')
        signature = signer.sign(h)
        return signature


    def verify_dsa_signature(self, data, signature, public_key):
        key = RSA.import_key(public_key)
        h = SHA256.new(data)
        verifier = DSS.new(key, 'fips-186-3')
        try:
            verifier.verify(h, signature)
            return True
        except ValueError:
            return False

    def encrypt_interface(self):
        file_path = filedialog.askopenfilename(title="Select a file for encryption")
        if not file_path:
            return

        encryption_window = tk.Toplevel(self.master)
        encryption_window.title("Encryption Interface")
        encryption_window.geometry("300x250")

        encryption_window.configure(bg='#f0f0f0')

        algorithm_label = tk.Label(encryption_window, text="Choose Encryption Algorithm:", font=("Helvetica", 12),
                                   bg='#f0f0f0')
        algorithm_label.pack(pady=10)

        button_style = {
            'font': ('Helvetica', 10),
            'bg': '#4CAF50',
            'fg': 'white',
            'padx': 10,
            'pady': 5,
            'border': 2,
            'relief': 'ridge'
        }

        aes_button = tk.Button(encryption_window, text="AES", command=lambda: self.encrypt_aes_file(file_path),
                               **button_style)
        aes_button.pack(pady=10)

        rsa_button = tk.Button(encryption_window, text="RSA", command=lambda: self.encrypt_rsa_file(file_path),
                               **button_style)
        rsa_button.pack(pady=10)

        dsa_button = tk.Button(
            encryption_window,
            text="DSA",
            command=lambda: self.sign_data_with_dsa_file(file_path),
            **button_style
        )

        dsa_button.pack(pady=10)

        encryption_window.mainloop()


    def verify_dsa_signature_file(self, file_path):
        public_key = self.get_dsa_public_key_from_user_or_file()
        if not public_key:
            return

        with open(file_path, "rb") as file:
            data = file.read()

        signature_file_path = filedialog.askopenfilename(
            title="Select DSA Signature File", filetypes=[("Signature Files", "*.sig")]
        )
        if not signature_file_path:
            return

        with open(signature_file_path, "rb") as signature_file:
            signature = signature_file.read()

        if self.verify_dsa_signature(data, signature, public_key):
            messagebox.showinfo("DSA Verification", "DSA signature is valid!")
        else:
            messagebox.showerror("DSA Verification", "DSA signature is invalid.")

    def get_dsa_public_key_from_user_or_file(self):
        return None

    def sign_data_with_dsa_file(self, file_path):
        private_key, public_key = self.generate_dsa_keypair()

        with open(file_path, "rb") as file:
            data = file.read()

        signature = self.sign_data_with_dsa(data, private_key)

        signature_file_path = filedialog.asksaveasfilename(
            title="Save DSA Signature As", defaultextension=".sig"
        )
        with open(signature_file_path, "wb") as signature_file:
            signature_file.write(signature)

        messagebox.showinfo("DSA Signature", "DSA signature created and saved.")

    def decrypt_interface(self):
        file_path = filedialog.askopenfilename(title="Select a file for decryption")
        if not file_path:
            return

        decryption_window = tk.Toplevel(self.master)
        decryption_window.title("Decryption Interface")
        decryption_window.geometry("300x250")

        decryption_window.configure(bg='#f0f0f0')


        method_label = tk.Label(decryption_window, text="Choose Decryption Method:", font=("Helvetica", 12),
                                bg='#f0f0f0')
        method_label.pack(pady=10)

        button_style = {
            'font': ('Helvetica', 10),
            'bg': '#4CAF50',
            'fg': 'white',
            'padx': 10,
            'pady': 5,
            'border': 2,
            'relief': 'ridge'
        }

        aes_button = tk.Button(decryption_window, text="AES", command=lambda: self.decrypt_aes_file(file_path),
                               **button_style)
        aes_button.pack(pady=10)

        rsa_button = tk.Button(decryption_window, text="RSA", command=lambda: self.decrypt_rsa_file(file_path),
                               **button_style)
        rsa_button.pack(pady=10)

        dsa_button = tk.Button(decryption_window, text="DSA", command=lambda: self.verify_dsa_signature_file(file_path),
                               **button_style)
        dsa_button.pack(pady=10)

        decryption_window.mainloop()

    def verify_dsa_signature_file(self, file_path):
        public_key = self.get_dsa_public_key_from_user_or_file()
        if not public_key:
            return

        with open(file_path, "rb") as file:
            data = file.read()

        signature_file_path = filedialog.askopenfilename(
            title="Select DSA Signature File", filetypes=[("Signature Files", "*.sig")]
        )
        if not signature_file_path:
            return

        with open(signature_file_path, "rb") as signature_file:
            signature = signature_file.read()

        if self.verify_dsa_signature(data, signature, public_key):
            messagebox.showinfo("DSA Verification", "DSA signature is valid!")
        else:
            messagebox.showerror("DSA Verification", "DSA signature is invalid.")



    def encrypt_aes_file(self, file_path):
        key = self.generate_aes_key()
        with open(file_path, "rb") as file:
            data = file.read()

        ciphertext, nonce, tag = self.encrypt_aes(data, key)

        encrypted_file_path = filedialog.asksaveasfilename(title="Save Encrypted File As", defaultextension=".enc")
        with open(encrypted_file_path, "wb") as encrypted_file:
            encrypted_file.write(nonce + tag + ciphertext)

        key_txt_file_path = encrypted_file_path + "_AES_key.txt"
        key_base64 = base64.b64encode(key).decode('utf-8')
        with open(key_txt_file_path, "w") as key_txt_file:
            key_txt_file.write(key_base64)

        self.update_keys_info("AES", key_txt_file_path, key_base64)

        messagebox.showinfo("Encryption Complete", "File encrypted successfully!\nAES key saved.")

    def encrypt_rsa_file(self, file_path):
        private_key, public_key = self.generate_rsa_keypair()
        with open(file_path, "rb") as file:
            data = file.read()

        ciphertext = self.encrypt_rsa(data, public_key)

        encrypted_file_path = filedialog.asksaveasfilename(title="Save Encrypted File As", defaultextension=".enc")
        with open(encrypted_file_path, "wb") as encrypted_file:
            encrypted_file.write(ciphertext)

        key_txt_file_path = encrypted_file_path + "_RSA_private_key.txt"
        with open(key_txt_file_path, "w") as key_txt_file:
            key_txt_file.write(private_key)

        self.update_keys_info("RSA", key_txt_file_path, private_key)

        messagebox.showinfo("Encryption Complete", "File encrypted successfully!\nRSA private key saved.")

    def decrypt_interface(self):
        file_path = filedialog.askopenfilename(title="Select a file for decryption")
        if not file_path:
            return

        decryption_window = tk.Toplevel(self.master)
        decryption_window.title("Decryption Interface")
        decryption_window.geometry("300x250")

        decryption_window.configure(bg='#f0f0f0')

        method_label = tk.Label(decryption_window, text="Choose Decryption Method:", font=("Helvetica", 12),
                                bg='#f0f0f0')
        method_label.pack(pady=10)

        button_style = {
            'font': ('Helvetica', 10),
            'bg': '#4CAF50',
            'fg': 'white',
            'padx': 10,
            'pady': 5,
            'border': 2,
            'relief': 'ridge'
        }

        aes_button = tk.Button(decryption_window, text="AES", command=lambda: self.decrypt_aes_file(file_path),
                               **button_style)
        aes_button.pack(pady=10)

        rsa_button = tk.Button(decryption_window, text="RSA", command=lambda: self.decrypt_rsa_file(file_path),
                               **button_style)
        rsa_button.pack(pady=10)

        decryption_window.mainloop()

    def decrypt_aes_file(self, file_path):
        key_label = tk.Label(self.master, text="Enter Decryption Key:")
        key_label.pack()

        key_entry = tk.Entry(self.master, show="*")
        key_entry.pack()

        def decrypt():
            key_text = key_entry.get()
            key = base64.b64decode(key_text)
            try:
                self.decrypt_aes_with_key_file(file_path, key)
            except ValueError:
                messagebox.showerror("Decryption Error", "Invalid key or corrupted file.")

        decrypt_button = tk.Button(self.master, text="Decrypt", command=decrypt)
        decrypt_button.pack()

        def load_key_file():
            key_file_path = filedialog.askopenfilename(title="Select AES Key File", filetypes=[("Key Files", "*.txt")])
            if key_file_path:
                with open(key_file_path, "r") as key_file:
                    key_entry.delete(0, tk.END)
                    key_entry.insert(0, key_file.read().strip())

        key_file_button = tk.Button(self.master, text="Load Key File", command=load_key_file)
        key_file_button.pack()

    def decrypt_aes_with_key_file(self, file_path, key):
        with open(file_path, "rb") as encrypted_file:
            data = encrypted_file.read()

        nonce = data[:16]
        tag = data[16:32]
        ciphertext = data[32:]

        try:
            decrypted_data = self.decrypt_aes(ciphertext, key, nonce, tag)
            decrypted_file_path = filedialog.asksaveasfilename(
                title="Save Decrypted File As", defaultextension=".txt"
            )
            with open(decrypted_file_path, "wb") as decrypted_file:
                decrypted_file.write(decrypted_data)

            messagebox.showinfo("Decryption Complete", "File decrypted successfully!")
        except ValueError:
            messagebox.showerror("Decryption Error", "Invalid key or corrupted file.")

    def decrypt_rsa_file(self, file_path):
        key_file_path = filedialog.askopenfilename(title="Select RSA Private Key File")
        if not key_file_path:
            return

        with open(key_file_path, "r") as key_file:
            private_key = key_file.read()

        try:
            self.decrypt_rsa_with_key_file(file_path, private_key)
        except ValueError:
            messagebox.showerror("Decryption Error", "Invalid key or corrupted file.")

    def decrypt_rsa_with_key_file(self, file_path, private_key):
        with open(file_path, "rb") as encrypted_file:
            ciphertext = encrypted_file.read()

        try:
            decrypted_data = self.decrypt_rsa(ciphertext, private_key)
            decrypted_file_path = filedialog.asksaveasfilename(
                title="Save Decrypted File As", defaultextension=".txt"
            )
            with open(decrypted_file_path, "wb") as decrypted_file:
                decrypted_file.write(decrypted_data)

            messagebox.showinfo("Decryption Complete", "File decrypted successfully!")
        except ValueError:
            messagebox.showerror("Decryption Error", "Invalid key or corrupted file.")

    def update_keys_info(self, algorithm, key_path, key_content):
        cursor = self.keys_connection.cursor()
        cursor.execute('''
            INSERT INTO keys (algorithm, key_path, key_content, key_length)
            VALUES (?, ?, ?, ?)
        ''', (algorithm, key_path, key_content, len(key_content)))
        self.keys_connection.commit()

    def show_keys_interface(self):
        password_dialog = tk.Toplevel(self.master)
        password_dialog.title("Enter Password")

        password_label = tk.Label(password_dialog, text="Enter Password:")
        password_label.pack()

        password_entry = tk.Entry(password_dialog, show="*")
        password_entry.pack()

        submit_button = tk.Button(password_dialog, text="Submit",
                                  command=lambda: self.authenticate_keys_password(password_entry.get(),
                                                                                  password_dialog))
        submit_button.pack()

    def authenticate_keys_password(self, entered_password, password_dialog):
        if entered_password == "louaykeys":
            password_dialog.destroy()
            self.display_keys_information()
        else:
            messagebox.showerror("Authentication Failed", "Incorrect password. Please try again.")

    def display_keys_information(self):
        keys_window = tk.Toplevel(self.master)
        keys_window.title("Keys Information Interface")

        keys_label = tk.Label(keys_window, text="Keys Information:")
        keys_label.grid(row=0, column=0, pady=10)

        tree = ttk.Treeview(keys_window, columns=("Algorithm", "Key Path", "Key Content"), show="headings", height=15,
                            selectmode='browse')

        tree.heading("Algorithm", text="Algorithm")
        tree.heading("Key Path", text="Key Path")
        tree.heading("Key Content", text="Key Content")

        tree_scrollbar = ttk.Scrollbar(keys_window, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=tree_scrollbar.set)

        tree.grid(row=1, column=0, sticky="nsew", padx=10)
        tree_scrollbar.grid(row=1, column=1, sticky="ns")

        def open_selected_key():
            selected_item = tree.selection()
            if selected_item:
                key_content = tree.item(selected_item, "values")[
                    2]
                self.open_key_content_window(key_content)
            else:
                messagebox.showinfo("No Key Selected", "Please select a key to open.")

        open_button = tk.Button(keys_window, text="Open Key", command=open_selected_key)
        open_button.grid(row=2, column=0, pady=10)

        cursor = self.keys_connection.cursor()
        cursor.execute('SELECT algorithm, key_path, key_content, id FROM keys')
        keys_data = cursor.fetchall()

        for key_info in keys_data:
            tree.insert("", tk.END, values=key_info[:3])

        keys_window.grid_rowconfigure(1, weight=1)
        keys_window.grid_columnconfigure(0, weight=1)

        keys_window.mainloop()
    def open_key_content_window(self, key_content):
        key_window = tk.Toplevel(self.master)
        key_window.title("Key Content")

        key_label = tk.Label(key_window, text="Key Content:")
        key_label.pack()

        key_text = tk.Text(key_window, wrap="word", height=10, width=50)
        key_text.insert(tk.END, key_content)
        key_text.pack()

        key_window.mainloop()


def main():
    root = tk.Tk()
    login_app = EncryptionApp(root)
    root.mainloop()

if __name__ == "__main__":
    root = tk.Tk()
    initial_app = InitialApp(root)
    root.mainloop()
