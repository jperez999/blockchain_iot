import time
import json
import binascii
import logging
import block_args as args
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pss


log = logging.getLogger()

class block(object):

    def __init__(self, index, previous_signed,  data, public_key,
                 time_st=time.time(), signed=None):
        self.index = index
        self.prev_signed = previous_signed
        self.timestamp = time_st
        self.data = data
        self.public_key = public_key
        self.signed = signed

    def create_hash(self, private_key):
        log.info("in block hash function...")
        key = RSA.import_key(private_key)
        if self.signed is not None:
            return self.signed
        log.info("making the HMAC for block")
        payload = str(self.data) + str(self.prev_signed) + str(self.index) + str(self.timestamp)
#        payload = str(self.data) + str(self.prev_signed) + str(self.index) + str(self.timestamp)
        signer = SHA256.new(data=payload.encode())
        # create signature using index, data, previous_hash and private key
        # signer.update(payload.encode())
        self.signed = pss.new(key).sign(signer).hex()

    # def __repr__(self):
    #     return '{\n\n "index": ' + str(self.index) + '\n\n"prev_signed": ' + str(self.prev_signed) + '\n\n "timestamp": ' + str(self.timestamp) + '\n\n"data": ' + str(self.data) + '\n\n"public_key": ' + str(self.public_key) + '\n\n"signature": ' + str(self.signed) + "\n\n}\n\n"

    def __repr__(self):
        res = {}
        res['index'] = int(self.index),
        res['prev_signed'] = self.prev_signed,
        res['timestamp'] = self.timestamp,
        res['data'] = self.data,
        res['public_key'] = str(self.public_key),
        res['signature'] = str(self.signed)
        return json.dumps(res)


class blockChain(object):
    blocks = []
    peers = []
    master_file = "blockchain_key.pem"
    bc_k_file = "user_bc_key.pem"
    instance = None

    def __init__(self):
        if blockChain.instance:
            log.info('this is a singleton')
        else:
            blockChain.instance = self
        self.get_key_pair()
        blk = self.make_first_block()
        self.add_block(blk)

    @staticmethod
    def get_instance():
        if not blockChain.instance:
            blockChain()
        return blockChain.instance

    def refresh_blocks(self, blocks):
        log.info("REFRESH BLOCKS")
        log.info("legnth of blocks: %s" % (str(len(blocks))))
        # ask other peers for their chains
        self.blocks = blocks
        # compare response to your
        # take most current

    @staticmethod
    def gen_block(sub_filter, data):
        bc = blockChain.get_instance()
        blk = block(int(bc.blocks[-1].index) + 1, bc.blocks[-1].signed,
                    f"{sub_filter}|_#_|{data}", bc.public_key)
        blk.create_hash(bc.private_key)
        # log.info "block is ready", blk
        return blk

    @staticmethod
    def verify_block(block):
        bc = blockChain.get_instance()
        # log.info "VERIFYING", block
        if int(block.index) != 0 and int(block.index) != int(bc.blocks[-1].index) + 1:
            log.error("block incorrect index, consider refresh blocks")
            return
        log.info("block's pkey: %s", (block.index, block.public_key))
        key = RSA.import_key(bytes.fromhex(block.public_key))
        # TODO create_hash for block
        # payload = str(block.index) + "_:_" + str(block.data)
        payload = str(block.data) + str(block.prev_signed) + str(block.index) + str(block.timestamp)
        hasher = SHA256.new(payload.encode())
        log.info(hasher.digest())
        v = pss.new(key.publickey())
        try:
            v.verify(hasher, bytes.fromhex(block.signed))
            log.info("VERIFY Success")
            return True
        except Exception as err:
            log.error("FAILED Verify %s" % str(err))
            return False
            # compare to block hash
            # add block

    def add_block(self, block):
        if int(block.index) == len(self.blocks):
            log.info('adding new block')
            self.blocks.append(block)

    def gen_blockchain_key(self):
        key = RSA.generate(2048)
        self.private_key = key.export_key('PEM')
        self.public_key = key.publickey().export_key('DER').hex()
        prK_file = open(self.bc_k_file, "w")
        prK_file.write(str(self.private_key))
        prK_file.close()
        return self.public_key

    def get_key_pair(self):
        log.info("Looking for keys")
        try:
            encoded_key = open(self.bc_k_file, "r").read()
            key = RSA.import_key(encoded_key)
            self.public_key = key.publickey().export_key('DER').hex()
            self.private_key = key.export_key()
            log.info("Key found!")
            return self.public_key
        except Exception as e:
            log.info("Failed to get keys, creating... %s" % str(e))
            return self.gen_blockchain_key()

    def register(self):
        # self.get_peers()
        # send out registration block
        log.info("creating registration block")
        self.gen_block("Register", self.public_key)
        return True

    def voteopen(self):
        # self.get_peers()
        # send out registration block
        log.info("creating voting block")
        self.gen_block("Vote", f"Vote_Open_{args.current_vote + 1}")
        return True

    def make_first_block(self):
        key = RSA.importKey(open(self.master_file, "rb").read())
        blk = block(0, 0, "base_block", key.publickey().export_key())
        blk.create_hash(key.export_key())
        # self.blocks.append(blk)
        return blk

    def extract_block(self, block_data):
        log.info("EXTRACT")
        # log.info block_data
        log.info(block_data)
        blk_dict = json.loads(block_data)
        index = blk_dict["index"][0]
        prev_signed = blk_dict["prev_signed"][0]
        timestamp = blk_dict["timestamp"][0]
        data = blk_dict["data"][0]
        public_key = blk_dict["public_key"][0]
        log.info(public_key)
        signed = blk_dict["signature"]
        # log.info "extracted values for block", index, prev_signed, timestamp, signed
        return block(index, prev_signed, data, public_key, time_st=timestamp,
                     signed=signed)

    # def extract_block(self, block_data):
    #     log.info("EXTRACT")
    #     # log.info block_data
    #     blk_dict = json.loads(block_data)
    #     index = self.extract_field("index", block_data)
    #     prev_signed = self.extract_field("prev_signed", block_data)
    #     timestamp = self.extract_field("timestamp", block_data)
    #     data = self.extract_field("data", block_data)
    #     public_key = self.extract_field("public_key", block_data)
    #     log.info(public_key)
    #     signed = self.extract_field("signature", block_data)
    #     # log.info "extracted values for block", index, prev_signed, timestamp, signed
    #     return block(index, prev_signed, data, public_key, time_st=timestamp,
    #                  signed=signed)

    def extract_list_blocks(self, data):
        log.info("EXTRACTING LIST")
        # log.info data
        blocks = []
        data_split = data.split(',')
        for obj in data_split:
            blk = self.extract_block(obj)
            if blk:
                blocks.append(blk)
        return blocks

    def extract_field(self, field_name, data):
        sp_data = data.split('\\n\\n')
        for line in sp_data:
            if field_name in line:
                # log.info field_name, line
                res = line.split(': ')[-1]
                # log.info res
                return res