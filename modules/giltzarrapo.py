#!/usr/bin/python3
from printer import cprint, ecprint

import os
import sys
import math
import getopt
from getpass import getuser
from random import randint
from operator import itemgetter
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA, SHA256, SHA512
from Crypto.PublicKey import RSA

from Crypto.Random import atfork
import multiprocessing

# Declare event as global variable so children processes can access it
found_block = multiprocessing.Event()

class Giltzarrapo:
    def __init__(self, chunkSize = 512):
        # Check chunkSize is power of 2: https://stackoverflow.com/questions/29480680/finding-if-a-number-is-a-power-of-2-using-recursion
        if not bool(chunkSize and not (chunkSize & (chunkSize-1))): raise ValueError('chunkSize must be power of 2')

        self.chunkSize = chunkSize
        self.blocks = []
        self.info = {}
        self.status = None
        self.n_processes = multiprocessing.cpu_count()*2

    @staticmethod
    def generateRSApair(passphrase = "", dir = None, name = "giltza_rsa", RSAlen = 4096):
        """Generates RSA key pair"""
        # Check RSAlen is power of 2
        if not bool(RSAlen and not (RSAlen&(RSAlen-1))): raise ValueError('RSAlen must be power of 2')

        # Prepare the rsa template with path
        if dir != None:
            # Replace ~ for the user's home
            if '~' in dir : dir = '/home/{}/{}'.format(getuser(), dir[len(dir) - ''.join(list(reversed(dir))).index('~') + 1:])
            if dir[-1] is '/': dir = dir[:-1] # ensure no extra / at the end

            if not os.path.exists(dir) : raise ValueError('No such directory : {}'.format(dir))
            file_template = '{}/{}'.format(dir, name)
        else : file_template = '{}/{}'.format(os.getcwd(), name)

        # Prepare the rsa files path and names
        privKey = file_template
        pubKey = '{}.pub'.format(file_template)

        # Generate rsa pair
        key = RSA.generate(RSAlen, Random.new().read)
        try :
            with open(privKey, 'wb') as priv, open(pubKey, 'wb') as pub:
                priv.write(key.exportKey("PEM", passphrase = passphrase))
                pub.write(key.publickey().exportKey("PEM"))
        except PermissionError: raise PermissionError('Write permision denied at : {}'.format(file_template))
        return privKey, pubKey

    @staticmethod
    def entropy(string):
        """Calculates the Shannon entropy of a string"""

        # get probability of chars in string
        prob = [ float(string.count(c)) / len(string) for c in dict.fromkeys(list(string)) ]

        return (- sum([ p * math.log(p) / math.log(2.0) for p in prob ]))

    def selectBlock(self, tryLimit = 5):
        """Select the highest entropy block from a random set of blocks"""
        try_blocks = [randint(0, len(self.blocks) - 1) for _ in range(tryLimit)]
        blocks_entropy = { block_index : Giltzarrapo.entropy(self.blocks[block_index].hex()) for block_index in try_blocks}
        selected_block = max(blocks_entropy.items(), key = itemgetter(1))[0]

        return selected_block

    def verifySymetricBlock(self, selected_block, pubkey):
        if self.status is None : raise TypeError('Must have a readed file in memory')
        if not os.path.isfile(pubkey): raise ValueError('No such file or directory : {}'.format(pubkey))

        try : PUBkey = RSA.importKey(open(pubkey, "rb").read())
        except ValueError: raise KeyError('Wrong key format')
        except PermissionError: raise PermissionError('Read permission denied : {}'.format(pubkey))
        if PUBkey.has_private(): raise KeyError('Wrong key format')

        if type(selected_block) != int:
            raise ValueError('The selected block must be an int')
        if selected_block > len(self.blocks) - 1 or selected_block < 0:
            raise ValueError('The selected block ({}) must satisfy :\n\t{}\n\t{}'.format(selected_block,
                'selected block <= {}'.format(len(self.blocks) - 1),
                'selected block >= 0'
            ))

        if selected_block == len(self.blocks) - 1: b = self.blocks[-1] + os.urandom(self.chunkSize - len(self.blocks[-1]))
        else : b = self.blocks[selected_block]

        try: PUBkey.encrypt(b, 32)
        except : return False
        return True

    def _block_check(self, input_queue, output_val, num_blocks, passwd, PRIVkey):
        atfork() # https://stackoverflow.com/questions/16981503/pycrypto-assertionerrorpid-check-failed-rng-must-be-re-initialized-after-fo
        global found_block

        for i in iter(input_queue.get, None):
            if found_block.is_set(): break

            # Get RSA block and its hash
            rsa_block = b"".join([self.blocks[i+j] for j in range(num_blocks)])
            try: block_hash = SHA256.new(PRIVkey.decrypt(rsa_block) + bytes(passwd, encoding = 'utf-8')).digest()
            except ValueError: continue

            if SHA.new(block_hash).digest() == self.info['challenge']:
                output_val.value = i
                found_block.set()

    def findBlock(self, passwd, PRIVkey, num_blocks):

        # Compute indexes of RSA blocks from the original blocks 
        num_rsa_blocks = len(self.blocks) - (num_blocks-1)

        # Fast mode
        # Parallelizing this operation doesn't seem to yield better results
        if self.info['fast']:
            for i in range(num_rsa_blocks):
                if SHA512.new(bytes('{}{}{}'.format(self.info['challenge'].hex(), i, passwd), encoding='utf-8')).digest() == self.info["auth"]:
                    return i
            else: raise ValueError('The symetric block could not be found. It may be caused by a wrong password and/or privkey')

        # Bruteforce mode
        else:

            # Input/output variables for parallel processes
            # We don't need a queue for the output value, since there is only one valid block, unless there is a hash collision. Changing
            # the value for 'output_val' is atomic.
            # If there is a collision for two blocks, there is a possible race condition where the index for the second block overwrites
            # the first one, if the second process has already checked the 'found_block' flag in the current iteration in _block_check(). 
            input_queue = multiprocessing.Queue()
            output_val = multiprocessing.Value('i')

            # Reset flag
            global found_block
            found_block.clear()

            # Put indexes in queue and start parallel processes
            for i in range(num_rsa_blocks): input_queue.put(i)
            for _ in range(self.n_processes):
                multiprocessing.Process(
                    target=self._block_check,
                    args=(input_queue, output_val, num_blocks, passwd, PRIVkey),
                    daemon=True
                ).start()
                input_queue.put(None)

            # TODO: add timeout to .wait() so an exception can be raised in case the block is not found
            # Alternatively, initialize output_val to -1, join() processes and then check if output_val>=0
            found_block.wait()
            return output_val.value

    def readPlain(self, infile):
        blocks = []
        try :
            with open(infile, 'rb') as inf:
                bytes_read = inf.read(self.chunkSize)
                while bytes_read:
                    blocks.append(bytes_read)
                    bytes_read = inf.read(self.chunkSize)
        except PermissionError:
            raise PermissionError('Read permission denied : {}'.format(infile))
        except FileNotFoundError:
            raise ValueError('No such file or directory : {}'.format(infile))

        self.blocks = blocks
        self.status = "plain"
        return self

    def encrypt(self, passwd, pubkey, selected_block = None, fast = True, try_max = 10):
        try:
            if try_max > 0: self._encrypt(passwd, pubkey, selected_block, fast)
        except (KeyError, PermissionError) as e: raise e
        except ValueError:
            if selected_block == None: self.encrypt(passwd, pubkey, selected_block, fast, try_max - 1)
            if self.status is not 'encrypted': raise ValueError('Error in RSA encryption for block {}'.format(selected_block))

        return self

    def _encrypt(self, passwd, pubkey, selected_block = None, fast = True):

        # Read public key
        try : PUBkey = RSA.importKey(open(pubkey, "r").read())
        except FileNotFoundError: raise ValueError('No such file or directory : {}'.format(pubkey))
        except ValueError: raise KeyError('Wrong key format')
        except PermissionError: raise PermissionError('Read permission denied : {}'.format(pubkey))
        if PUBkey.has_private(): raise KeyError('Wrong key format')

        # Select a valid block as symetric key
        if selected_block == None: selected_block = self.selectBlock()
        else:
            if type(selected_block) != int:
                raise ValueError('The selected block must be an int')
            if selected_block > len(self.blocks) - 1 or selected_block < 0:
                raise ValueError('The selected block ({}) must satisfy :\n\t{}\n\t{}'.format(selected_block,
                    'selected block <= {}'.format(len(self.blocks) - 1),
                    'selected block >= 0'
                ))

        # Padding
        block_size = len(self.blocks[-1])
        self.blocks[-1] = self.blocks[-1] + os.urandom(self.chunkSize - block_size)

        #Get the symetric encryptor
        hash_sha = SHA256.new(self.blocks[selected_block] + bytes(passwd, encoding = 'utf-8')).digest()
        hash_sha_sha = SHA.new(hash_sha).digest()
        encryptor = AES.new(hash_sha, AES.MODE_ECB, "")

        # Store the info
        self.info['fast'] = fast
        self.info['padding'] = self.chunkSize - block_size
        self.info['challenge'] = hash_sha_sha
        self.info['auth'] = SHA512.new(bytes('{}{}{}'.format(hash_sha_sha.hex(), selected_block, passwd), encoding='utf-8')).digest()

        # Encrypt the file
        for i,b in enumerate(self.blocks):
            self.blocks[i] = PUBkey.encrypt(b, 32)[0] if (i == selected_block) else encryptor.encrypt(b)

        self.status = "encrypted"
        return self

    def readEncrypted(self, infile, authfile = None):
        if not os.path.isfile(infile): raise ValueError('No such file or directory : {}'.format(infile))

        blocks = []
        info = {}
        try :
            with open(infile, 'rb') as inf:
                info['fast'] = bool.from_bytes(inf.read(1), byteorder='little')
                info['padding'] = int.from_bytes(inf.read(2), byteorder='little')
                info['challenge'] = inf.read(20)
                if info['fast'] : info['auth'] = inf.read(64)

                bytes_read = inf.read(self.chunkSize)
                while bytes_read:
                    blocks.append(bytes_read)
                    bytes_read = inf.read(self.chunkSize)
        except PermissionError: raise PermissionError('Read permission denied : {}'.format(infile))
        except FileNotFoundError: raise FileNotFoundError('File not found : {}'.format(infile))

        # If the file is in fast mode but an auth file is provided, trust the auth from the encrypted file
        if (authfile is not None) and (info['fast'] is False):
            try:
                with open(authfile, 'rb') as authf: info['auth'] = authf.read(64)
                info['fast'] = True
            except PermissionError: raise PermissionError('Read permission denied : {}'.format(authfile))
            except FileNotFoundError: raise FileNotFoundError('File not found : {}'.format(authfile))

        self.blocks = blocks
        self.info = info
        self.status = "encrypted"

        return self

    def decrypt(self, passwd, privkey, passphrase, selected_block = None):

        # Read private key
        try: PRIVkey = RSA.importKey(open(privkey, "r").read(), passphrase = passphrase)
        except FileNotFoundError: raise ValueError('No such file or directory : {}'.format(privkey))
        except ValueError: raise ValueError('Wrong or required passphrase')
        except PermissionError: raise PermissionError('Read permission denied : {}'.format(privkey))
        if not PRIVkey.has_private(): raise KeyError('Wrong key format')

        num_blocks = round((PRIVkey.key.size() + 1) / (8 * self.chunkSize))

        # Found and check the selected block
        if selected_block == None:
            selected_block = self.findBlock(passwd, PRIVkey, num_blocks)

            # Merge some blocks at the selected one to reach rsa encryption output size
            for i in range(1, num_blocks): self.blocks[selected_block] += self.blocks[selected_block + i]
            del self.blocks[selected_block + 1:selected_block + num_blocks]

            # Get the hash used for symetric encryption
            block_hash = SHA256.new(PRIVkey.decrypt(self.blocks[selected_block]) + bytes(passwd, encoding = 'utf-8')).digest()
        else:
            if type(selected_block) != int:
                raise ValueError('The selected block must be an int')
            if selected_block > len(self.blocks) - 1 or selected_block < 0:
                raise ValueError('The selected block ({}) must satisfy :\n\t{}\n\t{}'.format(selected_block,
                    'selected block < {}'.format(len(self.blocks)),
                    'selected block >= 0'
                ))

            # Merge some blocks at the selected one to reach rsa encryption output size
            for i in range(1, num_blocks): self.blocks[selected_block] += self.blocks[selected_block + i]
            del self.blocks[selected_block + 1:selected_block + num_blocks]

            # Verify the challenge
            try : block_hash = SHA256.new(PRIVkey.decrypt(self.blocks[selected_block]) + bytes(passwd, encoding = 'utf-8')).digest()
            except : raise ValueError('Can not decrypt with {} as selected block'.format(selected_block))
            signature = SHA.new(block_hash).digest()
            if signature != self.info['challenge']: raise ValueError('Wrong selected block or wrong password')

        encryptor = AES.new(block_hash)

        # Decrypt the file
        for i,b in enumerate(self.blocks):
            mode = PRIVkey if (i == selected_block) else encryptor
            self.blocks[i] = mode.decrypt(b)[:self.chunkSize - self.info['padding']] if (i == (len(self.blocks) - 1)) else mode.decrypt(b)

        self.status = "plain"
        return self

    def save(self, outfile, authfile = None):
        if self.status == None: raise TypeError('There is no readed data to save')

        try :
            with open(outfile, 'wb') as outf:
                if self.status == 'encrypted':
                    # write whether or not the fast mode is enabled
                    outf.write(self.info['fast'].to_bytes(1, byteorder='little'))
                    # write 2 bytes for the last block padding
                    outf.write(self.info['padding'].to_bytes(2, byteorder='little'))
                    # write the 20bytes of the SHA1
                    outf.write(self.info['challenge'])
                    # write the 64 bytes of the sha512 of the salted password if fast is enabled
                    if self.info['fast'] : outf.write(self.info['auth'])

                for i,b in enumerate(self.blocks): outf.write(b)
        except PermissionError : raise PermissionError('Write permission denied : {}'.format(outfile))

        if authfile != None and self.status == 'encrypted':
            try:
                with open(authfile, 'wb') as authf: authf.write(self.info['auth'])
            except PermissionError : raise PermissionError('Write permission denied : {}'.format(authfile))

    def clear(self):
        self.blocks = []
        self.info = {}
        self.status = None
