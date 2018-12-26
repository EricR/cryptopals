# Challenge 11 - An ECB/CBC detection oracle
#
# https://cryptopals.com/sets/2/challenges/11

import secrets

def random_key():
    return secrets.token_bytes(16)

def encryption_oracle():
    key = random_key()
    
if __name__ == '__main__':
    print(random_key())