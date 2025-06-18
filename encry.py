import hashlib
import binascii
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.dialogs import Messagebox
from tkinter import scrolledtext

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SecureCrypt")
        self.root.geometry("800x650")
        self.style = ttk.Style("darkly")  # Try: 'cosmo', 'flatly', 'minty', etc.
        self.attempts_remaining = 3
        self.setup_ui()

    def setup_ui(self):
        """Create the main application interface"""
        # Header Frame
        header_frame = ttk.Frame(self.root, padding=10)
        header_frame.pack(fill=X, pady=(0, 10))
        
        ttk.Label(
            header_frame, 
            text="SecureCrypt", 
            font=('Helvetica', 24, 'bold'),
            bootstyle="primary"
        ).pack(side=LEFT)

        ttk.Label(
            header_frame, 
            text="XOR Encryption Tool", 
            font=('Helvetica', 12),
            bootstyle="secondary"
        ).pack(side=LEFT, padx=10)

        # Notebook for tabs
        self.notebook = ttk.Notebook(self.root, bootstyle="primary")
        self.notebook.pack(fill=BOTH, expand=YES, padx=10, pady=(0, 10))

        # Create tabs
        self.create_encrypt_tab()
        self.create_decrypt_tab()
        self.create_about_tab()

        # Status bar
        self.status_var = ttk.StringVar(value="Ready")
        status_bar = ttk.Label(
            self.root, 
            textvariable=self.status_var,
            relief=FLAT,
            anchor=W,
            bootstyle="secondary"
        )
        status_bar.pack(fill=X, side=BOTTOM, ipady=5)

    def create_encrypt_tab(self):
        """Create the encryption tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🔒 Encrypt")

        # Input frame
        input_frame = ttk.LabelFrame(tab, text="Plaintext Input", padding=15)
        input_frame.pack(fill=BOTH, expand=YES, padx=5, pady=5)

        self.encrypt_text = scrolledtext.ScrolledText(
            input_frame, 
            height=10, 
            wrap=WORD,
            font=('Consolas', 10)
        )
        self.encrypt_text.pack(fill=BOTH, expand=YES)
        
        # Password frame
        pass_frame = ttk.Frame(tab)
        pass_frame.pack(fill=X, padx=5, pady=(5, 0))

        ttk.Label(pass_frame, text="Password:").pack(side=LEFT, padx=(0, 5))
        self.encrypt_password = ttk.Entry(
            pass_frame, 
            show="•", 
            width=30,
            bootstyle="primary"
        )
        self.encrypt_password.pack(side=LEFT, fill=X, expand=YES)

        # Button frame
        btn_frame = ttk.Frame(tab)
        btn_frame.pack(fill=X, padx=5, pady=10)

        ttk.Button(
            btn_frame,
            text="Encrypt",
            command=self.encrypt,
            bootstyle="success-outline",
            width=10
        ).pack(side=LEFT)

        # Output frame
        output_frame = ttk.LabelFrame(tab, text="Encrypted Output (Hexadecimal)", padding=15)
        output_frame.pack(fill=BOTH, expand=YES, padx=5, pady=5)

        self.encrypt_output = scrolledtext.ScrolledText(
            output_frame, 
            height=8, 
            wrap=WORD,
            font=('Consolas', 10),
            state=DISABLED
        )
        self.encrypt_output.pack(fill=BOTH, expand=YES)

        # Copy button
        ttk.Button(
            output_frame,
            text="Copy to Clipboard",
            command=self.copy_encrypted,
            bootstyle="info-outline",
            width=15
        ).pack(pady=(5, 0))

    def create_decrypt_tab(self):
        """Create the decryption tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🔓 Decrypt")

        # Input frame
        input_frame = ttk.LabelFrame(tab, text="Encrypted Input (Hexadecimal)", padding=15)
        input_frame.pack(fill=BOTH, expand=YES, padx=5, pady=5)

        self.decrypt_text = scrolledtext.ScrolledText(
            input_frame, 
            height=10, 
            wrap=WORD,
            font=('Consolas', 10)
        )
        self.decrypt_text.pack(fill=BOTH, expand=YES)
        
        # Password frame
        pass_frame = ttk.Frame(tab)
        pass_frame.pack(fill=X, padx=5, pady=(5, 0))

        ttk.Label(pass_frame, text="Password:").pack(side=LEFT, padx=(0, 5))
        self.decrypt_password = ttk.Entry(
            pass_frame, 
            show="•", 
            width=30,
            bootstyle="primary"
        )
        self.decrypt_password.pack(side=LEFT, fill=X, expand=YES)

        # Button frame
        btn_frame = ttk.Frame(tab)
        btn_frame.pack(fill=X, padx=5, pady=10)

        ttk.Button(
            btn_frame,
            text="Decrypt",
            command=self.decrypt,
            bootstyle="danger-outline",
            width=10
        ).pack(side=LEFT)

        # Output frame
        output_frame = ttk.LabelFrame(tab, text="Decrypted Output", padding=15)
        output_frame.pack(fill=BOTH, expand=YES, padx=5, pady=5)

        self.decrypt_output = scrolledtext.ScrolledText(
            output_frame, 
            height=8, 
            wrap=WORD,
            font=('Consolas', 10),
            state=DISABLED
        )
        self.decrypt_output.pack(fill=BOTH, expand=YES)

        # Copy button
        ttk.Button(
            output_frame,
            text="Copy to Clipboard",
            command=self.copy_decrypted,
            bootstyle="info-outline",
            width=15
        ).pack(pady=(5, 0))

    def create_about_tab(self):
        """Create the about tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="ℹ️ About")

        content = """SecureEncrypt - XOR Encryption Tool by Haseeb ur Rahman

Version: 1.0
Author: Haseeb ur Rahman

🔒 Features:
- XOR-based encryption/decryption
- Password verification with PBKDF2-HMAC-SHA256
- Secure password handling
- Modern GUI interface

⚠️ Security Note:
This tool provides basic encryption for educational purposes.
For highly sensitive data, consider more advanced solutions.

License: MIT Open Source
"""

        about_text = scrolledtext.ScrolledText(
            tab, 
            wrap=WORD,
            font=('Helvetica', 11),
            padx=20,
            pady=20
        )
        about_text.insert(END, content)
        about_text.configure(state=DISABLED)
        about_text.pack(fill=BOTH, expand=YES)

        # Footer
        footer = ttk.Frame(tab)
        footer.pack(fill=X, pady=10)
        ttk.Label(
            footer, 
            text="© 2023 Your Company", 
            bootstyle="secondary",
            anchor=CENTER
        ).pack(fill=X)

    def xor_encrypt_decrypt(self, data, key):
        """XOR encrypt/decrypt data with key"""
        key_bytes = key.encode('utf-8')
        data_bytes = data.encode('utf-8') if isinstance(data, str) else data
        return bytes([data_bytes[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(data_bytes))])

    def generate_password_hash(self, password):
        """Generate a secure hash of the password for verification"""
        salt = hashlib.sha256(password.encode('utf-8')).hexdigest()[:16].encode('utf-8')
        return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000).hex()

    def encrypt(self):
        """Encrypt plaintext with password verification"""
        plaintext = self.encrypt_text.get("1.0", END).strip()
        password = self.encrypt_password.get().strip()

        if not plaintext:
            Messagebox.show_error("Please enter text to encrypt", "Input Error")
            return
        
        if not password:
            Messagebox.show_error("Password cannot be empty", "Input Error")
            return
        
        try:
            self.status_var.set("Encrypting...")
            self.root.update()
            
            # Generate verification data
            verification_hash = self.generate_password_hash(password)
            
            # Combine verification hash + plaintext
            combined_data = f"{verification_hash}:{plaintext}"
            
            # XOR encrypt the combined data
            encrypted_data = self.xor_encrypt_decrypt(combined_data, password)
            
            # Convert to hex for display
            hex_data = binascii.hexlify(encrypted_data).decode('utf-8')
            
            # Display output
            self.encrypt_output.config(state=NORMAL)
            self.encrypt_output.delete("1.0", END)
            self.encrypt_output.insert("1.0", hex_data)
            self.encrypt_output.config(state=DISABLED)
            
            Messagebox.show_info("Text encrypted successfully!", "Success")
            self.status_var.set("Encryption complete")
        except Exception as e:
            Messagebox.show_error(f"Encryption failed: {str(e)}", "Error")
            self.status_var.set("Encryption failed")
        finally:
            self.root.update()

    def decrypt(self):
        """Decrypt encrypted text with password verification"""
        hex_data = self.decrypt_text.get("1.0", END).strip()
        password = self.decrypt_password.get().strip()

        if not hex_data:
            Messagebox.show_error("Please enter encrypted text", "Input Error")
            return
        
        if not password:
            Messagebox.show_error("Password cannot be empty", "Input Error")
            return
        
        try:
            encrypted_data = binascii.unhexlify(hex_data)
        except binascii.Error:
            Messagebox.show_error("Invalid hexadecimal input", "Error")
            return
        
        try:
            self.status_var.set("Decrypting...")
            self.root.update()
            
            # XOR decrypt the data
            decrypted_data = self.xor_encrypt_decrypt(encrypted_data, password).decode('utf-8')
            
            # Split verification hash and plaintext
            verification_hash, plaintext = decrypted_data.split(':', 1)
            
            # Verify password
            if verification_hash == self.generate_password_hash(password):
                # Display output
                self.decrypt_output.config(state=NORMAL)
                self.decrypt_output.delete("1.0", END)
                self.decrypt_output.insert("1.0", plaintext)
                self.decrypt_output.config(state=DISABLED)
                self.attempts_remaining = 3  # Reset attempts on success
                Messagebox.show_info("Decryption successful!", "Success")
                self.status_var.set("Decryption complete")
            else:
                self.attempts_remaining -= 1
                if self.attempts_remaining > 0:
                    Messagebox.show_warning(
                        f"Incorrect password! {self.attempts_remaining} attempts remaining.",
                        "Warning"
                    )
                    self.status_var.set(f"Wrong password - {self.attempts_remaining} attempts left")
                else:
                    Messagebox.show_error(
                        "Too many incorrect attempts. Exiting...",
                        "Security Alert"
                    )
                    self.root.after(1000, self.root.destroy)
        except (UnicodeDecodeError, ValueError):
            self.attempts_remaining -= 1
            if self.attempts_remaining > 0:
                Messagebox.show_warning(
                    f"Incorrect password or corrupted data! {self.attempts_remaining} attempts remaining.",
                    "Warning"
                )
                self.status_var.set(f"Decryption failed - {self.attempts_remaining} attempts left")
            else:
                Messagebox.show_error(
                    "Too many incorrect attempts. Exiting...",
                    "Security Alert"
                )
                self.root.after(1000, self.root.destroy)
        finally:
            self.root.update()

    def copy_encrypted(self):
        """Copy encrypted text to clipboard"""
        text = self.encrypt_output.get("1.0", END).strip()
        if text:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.status_var.set("Copied to clipboard!")
            self.root.update()

    def copy_decrypted(self):
        """Copy decrypted text to clipboard"""
        text = self.decrypt_output.get("1.0", END).strip()
        if text:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.status_var.set("Copied to clipboard!")
            self.root.update()

if __name__ == "__main__":
    app = ttk.Window("SecureCrypt", "darkly")  # Try other themes: 'cosmo', 'minty', etc.
    EncryptionApp(app)
    app.mainloop()