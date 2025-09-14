import pytest
import os
from PIL import Image
from PixelKey.core import encrypt_with_image_key, decrypt_with_image_key

# Define a dummy image path and region for testing
TEST_IMAGE_PATH = "test_image.png"
TEST_REGION = (5, 5, 10, 10)
TEST_MESSAGE = b"This is a secret test message."

@pytest.fixture(scope="module")
def setup_test_image():
    """
    Fixture to create a dummy image file for testing.
    This image will be created once for all tests in the module
    and cleaned up afterwards.
    """
    # Create a simple 20x20 red image
    img = Image.new('RGB', (20, 20), color = 'red')
    img.save(TEST_IMAGE_PATH)
    yield
    # Teardown: remove the dummy image file
    if os.path.exists(TEST_IMAGE_PATH):
        os.remove(TEST_IMAGE_PATH)

def test_encryption_decryption_flow(setup_test_image):
    """
    Tests the full encryption and decryption flow.
    """
    # Encrypt the message
    encrypted_packet = encrypt_with_image_key(TEST_MESSAGE, TEST_IMAGE_PATH, TEST_REGION)

    # Decrypt the message
    recovered_plaintext = decrypt_with_image_key(encrypted_packet, TEST_IMAGE_PATH)

    # Assert that the recovered plaintext matches the original message
    assert recovered_plaintext == TEST_MESSAGE

def test_invalid_region_coords():
    """
    Tests that decrypt_with_image_key raises ValueError if region_coords is missing from packet.
    """
    # Create a packet missing region_coords
    packet_missing_coords = {
        "ciphertext_b64": "some_ciphertext",
        "hidden_nonce_b64": "some_hidden_nonce",
    }
    with pytest.raises(ValueError, match="Packet missing region_coords"): # Updated expected error message
        decrypt_with_image_key(packet_missing_coords, TEST_IMAGE_PATH)
