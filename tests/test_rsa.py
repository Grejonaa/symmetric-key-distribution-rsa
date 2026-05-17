from crypto.rsa_utils import RSAUtils


def test_rsa():
    print("=" * 40)
    print("   TEST - RSAUtils")
    print("=" * 40)

    # 1. Gjenero çelesat
    private_key, public_key = RSAUtils.generate_keys()
    print("\n✔ Çelësat u gjeneruan!")

    # 2. Serialize
    pub_pem = RSAUtils.serialize_public_key(public_key)
    priv_pem = RSAUtils.serialize_private_key(private_key)
    print("✔ Serializimi u krye!")

    # 3. Load
    loaded_pub = RSAUtils.load_public_key(pub_pem)
    loaded_priv = RSAUtils.load_private_key(priv_pem)
    print("✔ Ngarkimi i çelësave u krye!")

    # 4. Enkriptim
    mesazhi = b"Test mesazh RSA"
    encrypted = RSAUtils.encrypt(loaded_pub, mesazhi)
    print(f"✔ Enkriptimi u krye: {encrypted[:20].hex()}...")

    # 5. Dekriptim
    decrypted = RSAUtils.decrypt(loaded_priv, encrypted)
    print(f"✔ Dekriptimi u krye: {decrypted.decode()}")

    # 6. Verifikimi
    print("\n" + "=" * 40)
    if mesazhi == decrypted:
        print("✔ SUCCESS - RSAUtils funksionon!")
    else:
        print("✗ GABIM - Diçka shkoi keq!")
    print("=" * 40)


if __name__ == "__main__":
    test_rsa()
