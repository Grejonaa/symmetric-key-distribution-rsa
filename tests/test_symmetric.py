from crypto.symmetric_utils import SymmetricUtils


def test_symmetric():
    print("=" * 40)
    print("   TEST - SymmetricUtils (AES)")
    print("=" * 40)

    try:
        # 1. Gjenero key
        key = SymmetricUtils.generate_key()
        print("\n✔ AES key u gjenerua!")

        # 2. Encrypt
        message = "Test mesazh AES-CBC"

        iv, ciphertext = SymmetricUtils.encrypt(key, message)
        print("✔ Enkriptimi u krye!")
        print(f"  IV (hex): {iv.hex()}")
        print(f"  Cipher (hex): {ciphertext.hex()[:30]}...")

        # 3. Decrypt
        decrypted = SymmetricUtils.decrypt(key, iv, ciphertext)
        print("✔ Dekriptimi u krye!")
        print(f"  Mesazhi: {decrypted}")

        # 4. Verifikimi
        print("\n" + "=" * 40)

        assert message == decrypted, "AES TEST FAILED!"

        print("✔ SUCCESS - SymmetricUtils funksionon!")
        print("=" * 40)

    except Exception as e:
        print("\n✗ GABIM gjatë testit AES!")
        print(f"Error: {e}")


if __name__ == "__main__":
    test_symmetric()