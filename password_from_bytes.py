import tkinter as tk
from tkinter import messagebox
import secrets
import base64


# Function to generate the password
def generate_password():
    try:
        length = int(length_entry.get())
        if length <= 0:
            raise ValueError

        # Generate random bytes
        random_bytes = secrets.token_bytes(length)

        # Convert bytes to a base64 encoded string and strip any padding
        password = base64.urlsafe_b64encode(random_bytes).rstrip(b'=').decode('utf-8')

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
window.geometry("400x200")

# Password length input with default value 24
length_label = tk.Label(window, text="Password Length:")
length_label.pack(pady=5)
length_entry = tk.Entry(window)
length_entry.insert(0, "24")  # Default value of 24
length_entry.pack(pady=5)

# Button to generate password
generate_button = tk.Button(window, text="Generate Password", command=generate_password)
generate_button.pack(pady=20)

# Entry to display generated password
password_entry = tk.Entry(window, width=50)
password_entry.pack(pady=5)

# Button to copy password, with no additional padding/margin
copy_button = tk.Button(window, text="Copy to Clipboard", command=copy_to_clipboard)
copy_button.pack(pady=0)

# Run the application
window.mainloop()
