"""
PixelKey AES-GCM encryption with nonce hidden in an image region.

This module provides functions for encrypting and decrypting messages using AES-GCM,
where the AES key is derived from the full image pixels using SHA256, and the
nonce is masked and hidden within a specific image region. This allows for
a unique and image-dependent cryptographic scheme.

Flow:
- Derive AES key from full image pixels: key = SHA256(full_image_pixels)
- Choose a small region (x, y, w, h). Derive region_key = SHA256(region_pixels).
- Create a random AES-GCM nonce (12 bytes).
- Mask the nonce with a deterministic mask produced via HMAC(region_key, b"nonce_mask")
  (take first 12 bytes of HMAC output). hidden_nonce = nonce XOR mask.
- Encrypt message with AES-GCM using aes_key and nonce.
- Send ciphertext and hidden_nonce (both can be base64 encoded for transport).

To decrypt:
- Receiver extracts the same region, derives region_key, recomputes mask,
  recovers nonce = hidden_nonce XOR mask, and uses that nonce + aes_key to decrypt.
"""

from PIL import Image
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import base64
import json
from typing import Tuple, Dict, Any

# -------------------------
# Utility helpers
# -------------------------
def sha256(data: bytes) -> bytes:
    """
    Computes the SHA256 hash of the given data.

    Args:
        data: The bytes object to hash.

    Returns:
        The 32-byte SHA256 hash as a bytes object.
    """
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()

def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """
    Computes the HMAC-SHA256 of the given data using the provided key.

    Args:
        key: The secret key for the HMAC.
        data: The data to be authenticated.

    Returns:
        The 32-byte HMAC-SHA256 tag as a bytes object.
    """
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    Performs a bitwise XOR operation on two bytes objects.

    Args:
        a: The first bytes object.
        b: The second bytes object.

    Returns:
        A new bytes object resulting from the XOR operation.
    """
    return bytes(x ^ y for x, y in zip(a, b))

# -------------------------
# Image handling & key derivation
# -------------------------
def load_image_as_rgb_bytes(image_path: str) -> Tuple[bytes, Tuple[int, int]]:
    """
    Load an image from the specified path, convert it to RGB format,
    and return its raw pixel bytes along with its width and height.
    The pixel data is in row-major order with R, G, B channels per pixel.

    Args:
        image_path: The file path to the image.

    Returns:
        A tuple containing:
        - pixel_bytes: Raw RGB pixel data as a bytes object (length = width * height * 3).
        - (width, height): A tuple representing the dimensions of the image.
    """
    img = Image.open(image_path).convert("RGB")
    w, h = img.size
    pixel_bytes = img.tobytes()  # length = w * h * 3
    return pixel_bytes, (w, h)

def extract_region_bytes(image_path: str, x: int, y: int, w: int, h: int) -> bytes:
    """
    Extracts a rectangular region from an image and returns its raw RGB pixel bytes.
    The coordinates (x, y) define the top-left corner of the region, and (w, h)
    define its width and height.

    Args:
        image_path: The file path to the image.
        x: The x-coordinate (column) of the top-left corner of the region.
        y: The y-coordinate (row) of the top-left corner of the region.
        w: The width of the region.
        h: The height of the region.

    Returns:
        Raw RGB pixel data for the extracted region as a bytes object.

    Raises:
        ValueError: If the specified region is out of the bounds of the image.
    """
    img = Image.open(image_path).convert("RGB")
    img_w, img_h = img.size
    if x < 0 or y < 0 or x + w > img_w or y + h > img_h:
        raise ValueError("Region out of bounds of the image")
    region = img.crop((x, y, x + w, y + h))
    return region.tobytes()

def derive_aes_key_from_image(image_path: str) -> bytes:
    """
    Derives a 32-byte AES key by computing the SHA256 hash of the entire
    image's RGB pixel data. This key is used for AES-GCM encryption.

    Args:
        image_path: The file path to the image.

    Returns:
        A 32-byte AES key as a bytes object.
    """
    pixel_bytes, _ = load_image_as_rgb_bytes(image_path)
    return sha256(pixel_bytes)  # 32 bytes

def derive_region_key(image_path: str, x: int, y: int, w: int, h: int) -> bytes:
    """
    Derives a 32-byte key from a specified image region by computing the
    SHA256 hash of that region's RGB pixel data. This key is used for
    masking the AES nonce.

    Args:
        image_path: The file path to the image.
        x: The x-coordinate (column) of the top-left corner of the region.
        y: The y-coordinate (row) of the top-left corner of the region.
        w: The width of the region.
        h: The height of the region.

    Returns:
        A 32-byte key as a bytes object derived from the image region.
    """
    region_bytes = extract_region_bytes(image_path, x, y, w, h)
    return sha256(region_bytes)

# -------------------------
# Encryption & Decryption
# -------------------------
def encrypt_with_image_key(plaintext: bytes, image_path: str, region_coords: Tuple[int, int, int, int]) -> Dict[str, Any]:
    """
    Encrypts plaintext data using AES-GCM. The AES key is derived from the full image,
    and the AES nonce is masked using an HMAC derived from a specified image region.
    The `region_coords` define the (x, y, width, height) of the image region used
    to mask the nonce.

    The function returns a dictionary suitable for transmission or storage, containing
    base64-encoded ciphertext and hidden nonce, along with the region coordinates
    (which can be omitted if the recipient already knows them).

    Args:
        plaintext: The data to be encrypted, as a bytes object.
        image_path: The file path to the image used for key derivation.
        region_coords: A tuple (x, y, w, h) specifying the top-left corner
                       and dimensions of the region used for nonce masking.

    Returns:
        A dictionary with the following keys:
        - "ciphertext_b64": Base64-encoded AES-GCM ciphertext (includes authentication tag).
        - "hidden_nonce_b64": Base64-encoded masked nonce.
        - "region_coords": A list [x, y, w, h] of the region coordinates.

    Note: If `region_coords` are sensitive, they should not be included in the
    returned packet for transmission.
    """
    # derive keys
    aes_key = derive_aes_key_from_image(image_path)  # 32 bytes
    x, y, w, h = region_coords
    region_key = derive_region_key(image_path, x, y, w, h)  # 32 bytes

    # AES-GCM nonce (12 bytes)
    nonce = os.urandom(12)

    # Create mask for nonce using HMAC(region_key, b"nonce_mask")
    mask_full = hmac_sha256(region_key, b"nonce_mask")  # 32 bytes
    mask = mask_full[:12]  # take first 12 bytes to mask the AES nonce

    hidden_nonce = xor_bytes(nonce, mask)  # this is safe to transmit; without region_key it's useless

    # Encrypt the plaintext using AES-GCM (AES-256)
    aesgcm = AESGCM(aes_key)
    # Optionally include associated data to bind ciphertext to some metadata. Here we omit or set None.
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)  # ciphertext contains tag appended

    # Return base64-encoded packet for easy transport/storage
    packet = {
        "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
        "hidden_nonce_b64": base64.b64encode(hidden_nonce).decode("ascii"),
        # tag length implicit; including coords is optional. If you include coords, recipients don't need prior agreement.
        "region_coords": [x, y, w, h]
    }
    return packet

def decrypt_with_image_key(packet: Dict[str, Any], image_path: str) -> bytes:
    """
    Decrypts an encrypted packet (generated by `encrypt_with_image_key`) using
    the same image and region coordinates.

    Args:
        packet: A dictionary containing the encrypted data, typically with keys:
                "ciphertext_b64", "hidden_nonce_b64", and "region_coords".
        image_path: The file path to the image used for key derivation and nonce recovery.

    Returns:
        The decrypted plaintext as a bytes object.

    Raises:
        ValueError: If "region_coords" is missing from the packet or if decryption fails
                    (e.g., due to incorrect key, nonce, or corrupted ciphertext).
    """
    # read fields
    ciphertext = base64.b64decode(packet["ciphertext_b64"])
    hidden_nonce = base64.b64decode(packet["hidden_nonce_b64"])
    if "region_coords" not in packet:
        raise ValueError("Packet missing region_coords - receiver must know which region to use.")

    x, y, w, h = packet["region_coords"]
    # derive keys
    aes_key = derive_aes_key_from_image(image_path)
    region_key = derive_region_key(image_path, x, y, w, h)

    # recompute mask and recover nonce
    mask_full = hmac_sha256(region_key, b"nonce_mask")
    mask = mask_full[:12]
    nonce = xor_bytes(hidden_nonce, mask)

    # decrypt
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
