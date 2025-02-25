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

def encrypt_message(message, key):
    cipher = Fernet(key)
    return cipher.encrypt(message.encode()).decode()

def text_to_binary(text):
    return ''.join(format(ord(char), '08b') for char in text)

def encode_image():
    image_path = filedialog.askopenfilename(title="Select Image")
    if not image_path:
        return

    message = message_entry.get().strip()
    password = password_entry.get().strip()

    if not message or not password:
        messagebox.showerror("Error", "Message and password cannot be empty.")
        return

    key = generate_key(password)
    encrypted_message = encrypt_message(message, key)
    binary_message = text_to_binary(encrypted_message) + '1111111111111110'  

    image = cv2.imread(image_path)
    if image is None:
        messagebox.showerror("Error", "Failed to load the image.")
        return

    h, w, _ = image.shape
    total_pixels = h * w * 3

    if len(binary_message) > total_pixels:
        messagebox.showerror("Error", "Message is too large for this image.")
        return

    flat_image = image.flatten()

    for i in range(len(binary_message)):
        flat_image[i] = (flat_image[i] & 0xFE) | int(binary_message[i])

    encoded_image = np.reshape(flat_image, (h, w, 3)).astype(np.uint8)

    save_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])
    if save_path:
        cv2.imwrite(save_path, encoded_image)
        messagebox.showinfo("Success", "Message encoded and saved successfully!")
root = tk.Tk()
root.title("Image Encoder")
root.geometry("400x200")
frame = tk.Frame(root, padx=10, pady=10)
frame.pack(padx=10, pady=10)
tk.Label(frame, text="Message:", font=("Arial", 12)).grid(row=0, column=0, sticky="w", pady=5)
message_entry = tk.Entry(frame, width=40, font=("Arial", 12))
message_entry.grid(row=0, column=1, pady=5)
tk.Label(frame, text="Password:", font=("Arial", 12)).grid(row=1, column=0, sticky="w", pady=5)
password_entry = tk.Entry(frame, width=40, show="*", font=("Arial", 12))
password_entry.grid(row=1, column=1, pady=5)
encode_button = tk.Button(frame, text="Upload Image & Encode", command=encode_image, font=("Arial", 12), bg="blue", fg="white")
encode_button.grid(row=2, columnspan=2, pady=10)
root.mainloop()
