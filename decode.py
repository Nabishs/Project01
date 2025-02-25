import cv2
import numpy as np
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
import base64
import hashlib

def generate_key(password):
    key = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(key)

def binary_to_text(binary_data):
    chars = [chr(int(binary_data[i:i+8], 2)) for i in range(0, len(binary_data), 8)]
    return ''.join(chars)

def decrypt_message(encrypted_message, key):
    try:
        cipher = Fernet(key)
        return cipher.decrypt(encrypted_message.encode()).decode()
    except Exception:
        return None

def decode_image():
    image_path = filedialog.askopenfilename(title="Select Encoded Image")
    if not image_path:
        return

    password = password_entry.get().strip()
    if not password:
        messagebox.showerror("Error", "Password cannot be empty.")
        return

    image = cv2.imread(image_path)
    if image is None:
        messagebox.showerror("Error", "Failed to load the image.")
        return

    flat_image = image.flatten()

    binary_message = ""
    for pixel in flat_image:
        binary_message += str(pixel & 1)

    end_marker = "1111111111111110"
    end_index = binary_message.find(end_marker)
    
    if end_index == -1:
        messagebox.showerror("Error", "No hidden message found.")
        return

    binary_message = binary_message[:end_index]
    encrypted_message = binary_to_text(binary_message)

    key = generate_key(password)
    decrypted_message = decrypt_message(encrypted_message, key)

    if decrypted_message is None:
        messagebox.showerror("Error", "Incorrect password or corrupted data.")
        return

    messagebox.showinfo("Decoded Message", f"Hidden Message:\n{decrypted_message}")
root = tk.Tk()
root.title("Image Decoder")
root.geometry("400x150")
frame = tk.Frame(root, padx=10, pady=10)
frame.pack(padx=10, pady=10)
tk.Label(frame, text="Password:", font=("Arial", 12)).grid(row=0, column=0, sticky="w", pady=5)
password_entry = tk.Entry(frame, width=40, show="*", font=("Arial", 12))
password_entry.grid(row=0, column=1, pady=5)
decode_button = tk.Button(frame, text="Upload Image & Decode", command=decode_image, font=("Arial", 12), bg="green", fg="white")
decode_button.grid(row=1, columnspan=2, pady=10)
root.mainloop()
