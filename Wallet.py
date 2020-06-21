from tinyec.ec import SubGroup, Curve
from Crypto.Random.random import randint
from web3 import Web3
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import json

# Wallet Generation
def generate_wallet(wallet_password):
    # __________________________________________________________________________________________________________________
    # SECP256K1 PARAMETERS FOR EC CRYPTOGRAPHY

    p = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
    n = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
    h = 1

    # __________________________________________________________________________________________________________________
    # ELLIPTIC CURVE DEFINITION

    x = int("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            16)  # See "Recommended Eliptic Curve Domain Parameters" Paper
    y = int("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
    g = (x, y)

    field = SubGroup(p, g, n, h)
    curve = Curve(a=0, b=7, field=field, name='secp2561k')  # Object creation for the elliptic curve

    # __________________________________________________________________________________________________________________
    # PRIVATE/PUBLIC KEY GENERATION THROUGH 'ELLIPTIC CURVE POINT MULTIPLICATION'
    private_key = randint(1, n)
    #private_key = int("f8f8a2f43c8376ccb0871305060d7b27b0554d2cc72bccf41b2705608452f315", 16) #example
    public_key = private_key * curve.g

    # The public key is generated as an added point to the elliptic curve g. To obtain this new point, the eliptic curve
    # is multiplied by an initial point, known as the private key. Even given the elliptic curve and new point,
    # it is not (easily) possible to find the initial point (i.e. the private key).

    # __________________________________________________________________________________________________________________
    # DERIVING THE ETHEREUM ADDRESS FROM PUBLIC KEY
    public_key_hex = Web3.toHex(public_key.x)[2:] + Web3.toHex(public_key.y)[2:]  # Removing the 0x start using [2:]
    address = Web3.keccak(hexstr=public_key_hex).hex()
    address = Web3.toChecksumAddress('0x' + address[-40:])

    # 0x is added to the last 40 characters of the sha-256 encrypted public key to generate the Ethereum address. A
    # Checksum is applied to the result by capitalizing certain characters (purely for readability).

    # __________________________________________________________________________________________________________________
    # PASSWORD PROTECTION
    password = str(wallet_password).encode('utf-8')
    password = bytes(password)                           # Choose a password
    salt = get_random_bytes(16)                                 # Generate a random salt
    key = scrypt(password, salt, 32, N=2 ** 20, r=8, p=1)       # Generate a 32-byte encryption key from the password
                                                                # and salt, with CPU cost parameter 2**20

    private_key = Web3.toHex(private_key)[2:]                   # Convert existing private key to Hex format
    data = str(private_key).encode('utf-8')                     # Convert Hex key to string and encode into bytes
    cipher = AES.new(key, AES.MODE_CBC)                         # Call required AES encryption method
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))        # Encrypt private key 'data' using AES-256

    salt = salt.hex()                                           # Convert salt to hex
    iv = cipher.iv.hex()                                        # Convert initialization vector to hex
    ct = ct_bytes.hex()                                         # Convert encrypted private key to hex

    output = {'salt': salt, "initialization vector": iv, "encrypted private key": ct}

    with open(address + '.txt', 'w') as json_file:
        json.dump(output, json_file)

    print('Generated wallet:')
    print('     address: ', address)
    print()
    #print('Private key: ', private_key) Only print for testing

    return 0

# Wallet Access
def access_wallet(address, password):

    with open(address + '.txt') as f:
        data = json.load(f)

    salt = bytes.fromhex(data['salt'])
    iv = bytes.fromhex(data['initialization vector'])
    ct = bytes.fromhex(data['encrypted private key'])

    key = scrypt(password, salt, 32, N=2**20, r=8, p=1)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    private_key = unpad(cipher.decrypt(ct), AES.block_size)

    print('Accessed wallet:')
    print('address: ', address)
    print('Private key: ', private_key)
    print()

    return 0


action = input("\nGenerate or Access Python Wallet? \n1 - Generate Wallet \n2 - Access Wallet \n0 - Close Wallet \n")

while int(action) != 0:
    if int(action) == 0:
        print('Closing Wallet.')

    elif int(action) == 1:
        password = input('Choose Password: ')
        generate_wallet(password)

        action = input("Generate or Access Python Wallet? \n1 - Generate Wallet \n2 - Access Wallet \n0 - Close Wallet \n")

    elif int(action) == 2:
        address = input('Enter the address of the wallet you wish to access: ')
        password = input('Enter password: ')
        access_wallet(address, password)

        action = input("Generate or Access Python Wallet? \n1 - Generate Wallet \n2 - Access Wallet \n0 - Close Wallet \n")

    else:
        print('Invalid Input')

        action = input("Generate or Access Python Wallet? \n1 - Generate Wallet \n2 - Access Wallet \n0 - Close Wallet \n")






