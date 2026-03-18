# QuantaWeave GUI User Guide

The QuantaWeave GUI provides a user-friendly interface for post-quantum cryptography operations, including LWE encryption and Falcon signatures. This guide explains how to install, launch, and use the GUI for common cryptographic tasks.

## Installation

1. Ensure you have Python 3.8+ installed.
2. Install the required dependencies:
   ```bash
   python -m pip install .[gui]
   ```
3. (Optional) Build a standalone Windows executable:
   ```bash
   pyinstaller --noconfirm --clean QuantaWeaveGUI.spec
   # Output: dist/QuantaWeaveGUI.exe
   ```

## Launching the GUI

- From source:
  ```bash
  python gui/quantaweave_gui.py
  ```
- From the standalone EXE (if built):
  - Double-click `dist/QuantaWeaveGUI.exe`.

## Main Features

The GUI is organized into two tabs:

### 1. LWE Tab
- **Security Level:** Choose LEVEL1, LEVEL3, or LEVEL5.
- **Keypair:** Generate and view public/private keys (JSON format).
- **Encrypt:** Enter a message and public key, click Encrypt to produce ciphertext.
- **Decrypt:** Enter ciphertext and private key, click Decrypt to recover the message.

### 2. Falcon Tab
- **Parameter Set:** Choose Falcon-512 or Falcon-1024.
- **Keypair:** Generate Falcon public/secret keys.
- **Sign:** Sign a message with the secret key.
- **Verify:** Verify a signature with the public key.

## Step-by-Step Example: LWE Encryption/Decryption

1. Go to the **LWE** tab.
2. Select a security level (e.g., LEVEL1).
3. Click **Generate Keypair**. Public and private keys will appear.
4. Enter your message in the Message box.
5. Click **Encrypt**. The ciphertext will appear.
6. To decrypt, paste the ciphertext and private key, then click **Decrypt**. The original message will be shown.

## Step-by-Step Example: Falcon Sign/Verify

1. Go to the **Falcon** tab.
2. Select parameter set and encoding.
3. Click **Generate Keypair**.
4. Enter a message and click **Sign**. The signature will appear.
5. To verify, paste the public key, message, and signature, then click **Verify**. The result will show 'valid' or 'invalid'.

## Troubleshooting
- If you see errors about missing dependencies, ensure you installed with `[gui]` extras.
- For build errors, check that PyQt6 and PyInstaller are installed and up to date.
- If the GUI does not launch, try running from a terminal to see error messages.

## More Information
- For advanced usage, see the main README and docs/ALGORITHM.md.
- For issues, open a ticket on the GitHub repository.
