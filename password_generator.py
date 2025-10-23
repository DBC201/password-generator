import tkinter as tk
from tkinter import messagebox
import secrets
import string
import base64
import math


# Function to generate the password
def generate_password():
    try:
        length = int(length_entry.get())
        if length <= 0:
            raise ValueError
        
        password = ""
        
        if random_bytes_var.get():

            byte_len = math.ceil(length * 3 / 4)
            random_bytes = secrets.token_bytes(byte_len)

            password = base64.urlsafe_b64encode(random_bytes).decode('utf-8')
            password = password[:length]

            # Convert bytes to a base64 encoded string and strip any padding
            password = base64.urlsafe_b64encode(random_bytes).decode('utf-8')
        else:
            include_uppercase = uppercase_var.get()
            include_numbers = numbers_var.get()
            include_special = special_var.get()

            characters = string.ascii_lowercase
            if include_uppercase:
                characters += string.ascii_uppercase
            if include_numbers:
                characters += string.digits
            if include_special:
                characters += string.punctuation

            password = ''.join(secrets.choice(characters) for _ in range(length))
        password_entry.delete(0, tk.END)
        password_entry.insert(0, password)
    except ValueError:
        messagebox.showerror("Invalid Input", "Please enter a valid number for the password length.")


# Function to copy password to clipboard
def copy_to_clipboard():
    window.clipboard_clear()
    window.clipboard_append(password_entry.get())
    messagebox.showinfo("Copied", "Password copied to clipboard")


# Set up the UI
window = tk.Tk()
window.title("Password Generator")
window.geometry("400x300")

# Password length input
length_label = tk.Label(window, text="Password Length:")
length_label.pack(pady=5)
length_entry = tk.Entry(window)
length_entry.insert(0, "24")  # Set default length to 24
length_entry.pack(pady=5)

# Options for password components with default values set to True
uppercase_var = tk.BooleanVar(value=True)
uppercase_check = tk.Checkbutton(window, text="Include Uppercase Letters", variable=uppercase_var)
uppercase_check.pack(pady=5)

numbers_var = tk.BooleanVar(value=True)
numbers_check = tk.Checkbutton(window, text="Include Numbers", variable=numbers_var)
numbers_check.pack(pady=5)

special_var = tk.BooleanVar(value=True)
special_check = tk.Checkbutton(window, text="Include Special Characters", variable=special_var)
special_check.pack(pady=5)

random_bytes_var = tk.BooleanVar(value=False)
random_bytes_check = tk.Checkbutton(window, text="Use random bytes", variable=random_bytes_var)
random_bytes_check.pack(pady=5)

def use_random_bytes(*_):
    use_bytes = random_bytes_var.get()

    # Turn off other options & disable their controls if using bytes
    if use_bytes:
        uppercase_var.set(False)
        numbers_var.set(False)
        special_var.set(False)
        uppercase_check.config(state="disabled")
        numbers_check.config(state="disabled")
        special_check.config(state="disabled")
    else:
        # Re-enable controls; do not force values (user can choose)
        uppercase_check.config(state="normal")
        numbers_check.config(state="normal")
        special_check.config(state="normal")

random_bytes_var.trace_add("write", use_random_bytes)

# Button to generate password
generate_button = tk.Button(window, text="Generate Password", command=generate_password)
generate_button.pack(pady=20)

# Entry to display generated password
password_entry = tk.Entry(window, width=50)
password_entry.pack(pady=5)

# Button to copy password
copy_button = tk.Button(window, text="Copy to Clipboard", command=copy_to_clipboard)
copy_button.pack(pady=5)

# Run the application
window.mainloop()
