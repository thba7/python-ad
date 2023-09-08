from datetime import datetime
from os import urandom
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
import pytz
import json
import base64


class encryptor:
    def __init__(self, adyen_public_key, adyen_version='_0_1_8', adyen_prefix='adyenjs'):
        """
        :param adyen_public_key: adyen key, looks like this: "10001|A2370..."
        :param adyen_version: version of adyen encryption, looks like this: _0_1_8
        :param adyen_prefix: prefix before adyen version. can vary depending on where you are submitting the payment. typically is just "adyenjs"
        """

        self.adyen_public_key = adyen_public_key
        self.adyen_version = adyen_version
        self.adyen_prefix = adyen_prefix

    def encrypt_field(self, name: str, value: str):
        """
        :param name: name of field you want to encrypt, for ex, "cvc"
        :param value: value of the field you want to encrypt
        :return: a string containing the adyen-encrypted field
        """

        plain_card_data = self.field_data(name, value)
        card_data_json_string = json.dumps(plain_card_data, sort_keys=True)

        # Encrypt the actual card data with symmetric encryption
        aes_key = self.generate_aes_key()
        nonce = self.generate_nonce()
        encrypted_card_data = self.encrypt_with_aes_key(aes_key, nonce, bytes(card_data_json_string, encoding='utf-8'))
        encrypted_card_component = nonce + encrypted_card_data

        # Encrypt the AES Key with asymmetric encryption
        public_key = self.decode_adyen_public_key(self.adyen_public_key)
        encrypted_aes_key = self.encrypt_with_public_key(public_key, aes_key)

        return "{}{}${}${}".format(self.adyen_prefix,
                                   self.adyen_version,
                                   base64.standard_b64encode(encrypted_aes_key).decode(),
                                   base64.standard_b64encode(encrypted_card_component).decode())

    def encrypt_card(self, card: str, cvv: str, month: str, year: str):
        """
        :param card: card number string
        :param cvv: cvv number string
        :param month: card month string
        :param year: card year string
        :return: dictionary with all encrypted card fields (card, cvv, month, year)
        """

        data = {
            'card': self.encrypt_field('number', card),
            'cvv': self.encrypt_field('cvc', cvv),
            'month': self.encrypt_field('expiryMonth', month),
            'year': self.encrypt_field('expiryYear', year),
        }

        return data

    def field_data(self, name, value):
        """
        :param name: name of field
        :param value: value of field
        :return: a dict to be encrypted
        """

        generation_time = datetime.now(tz=pytz.timezone('UTC')).strftime('%Y-%m-%dT%H:%M:%S.000Z')
        field_data_json = {
            name: value,
            "generationtime": generation_time
        }

        return field_data_json

    def encrypt_from_dict(self, dict_: dict):
        plain_card_data = dict_
        card_data_json_string = json.dumps(plain_card_data, sort_keys=True)

        # Encrypt the actual card data with symmetric encryption
        aes_key = self.generate_aes_key()
        nonce = self.generate_nonce()
        encrypted_card_data = self.encrypt_with_aes_key(aes_key, nonce, bytes(card_data_json_string, encoding='utf-8'))
        encrypted_card_component = nonce + encrypted_card_data

        # Encrypt the AES Key with asymmetric encryption
        public_key = self.decode_adyen_public_key(self.adyen_public_key)
        encrypted_aes_key = self.encrypt_with_public_key(public_key, aes_key)

        return "{}{}${}${}".format(self.adyen_prefix,
                                   self.adyen_version,
                                   base64.standard_b64encode(encrypted_aes_key).decode(),
                                   base64.standard_b64encode(encrypted_card_component).decode())

    @staticmethod
    def decode_adyen_public_key(encoded_public_key):
        backend = default_backend()
        key_components = encoded_public_key.split("|")
        public_number = rsa.RSAPublicNumbers(int(key_components[0], 16), int(key_components[1], 16))
        return backend.load_rsa_public_numbers(public_number)

    @staticmethod
    def encrypt_with_public_key(public_key, plaintext):
        ciphertext = public_key.encrypt(plaintext, padding.PKCS1v15())
        return ciphertext

    @staticmethod
    def generate_aes_key():
        return AESCCM.generate_key(256)

    @staticmethod
    def encrypt_with_aes_key(aes_key, nonce, plaintext):
        cipher = AESCCM(aes_key, tag_length=8)
        ciphertext = cipher.encrypt(nonce, plaintext, None)
        return ciphertext

    @staticmethod
    def generate_nonce():
        return urandom(12)



from flask import Flask, jsonify, request

def adyen_enc(cc, mes, ano, cvv, ADYEN_KEY, adyen_version):
    enc = encryptor(ADYEN_KEY)
    enc.adyen_version = adyen_version
    enc.adyen_public_key = ADYEN_KEY

    card = enc.encrypt_card(card=cc, cvv=cvv, month=mes, year=ano)
    month = card['month']
    year = card['year']
    cvv = card['cvv']
    card = card['card']

    return {'card':card, 
            'month': month, 
            'year':year, 
            'cvv': cvv}

app = Flask(__name__)


@app.route('/')
def hola():
    return '''Bienvenido, para usar el bin info ingresa /bin/434256 <br>para usar el adyen encryp usar /adyen/?card=(card)?mes=(mes)?ano=(ano)?cvv=(cvv)?adyen_key=(adyen_key)?version=(version)'''


@app.route('/adyenpost', methods=['POST'])
def adyen():
    data = request.form
    
    if 'card' not in data or 'month' not in data or 'year' not in data or 'cvv' not in data or 'adyen_key' not in data or 'version' not in data:
        return 'Faltan parámetros', 400
    card = data['card']
    month = data['month']
    year = data['year']
    cvv = data['cvv']
    adyen_key = data['adyen_key']
    version = data['version']
    resul = adyen_enc(card, month, year, cvv, adyen_key, version)
    
    return {'card': resul['card'], 'month': resul['month'], 'year': resul['year'], 'cvv': resul['cvv']}


@app.route('/adyen/', methods=['GET'])
def adyen2():
    card = request.args.get('card')
    month = request.args.get('month')
    year = request.args.get('year')
    cvv = request.args.get('cvv')
    adyen_key = request.args.get('adyen_key')
    version = request.args.get('version')
    
    if not card or not month or not year or not cvv or not adyen_key or not version:
        return 'Faltan parámetros', 400
    
    resul = adyen_enc(card, month, year, cvv, adyen_key, version)
    
    return {'card': resul['card'], 'month': resul['month'], 'year': resul['year'], 'cvv': resul['cvv']}


if __name__ == '__main__':
    app.run(debug=True, port=5000)
