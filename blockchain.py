import time
import json
import logging
import block_args as args
from state_machine import ZMQ_Soc, BlockQueue
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pss
import requests


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
        log.info(f"making the HMAC for block {self.index}")
        payload = str(self.data) + str(self.prev_signed) + str(self.index) + str(self.timestamp)
#        payload = str(self.data) + str(self.prev_signed) + str(self.index) + str(self.timestamp)
        signer = SHA256.new(data=payload.encode())
        # create signature using index, data, previous_hash and private key
        # signer.update(payload.encode())
        self.signed = pss.new(key).sign(signer).hex()

    def __repr__(self):
        return f'\n"index": {self.index};\n"prev_signed": {self.prev_signed};\n"timestamp": {self.timestamp};\n"data": {self.data};\n"public_key": {self.public_key};\n"signature": {self.signed};\n'


class blockChain(object):
    blocks = []
    peers = []
    master_file = "blockchain_key.pem"
    bc_k_file = "user_bc_key.pem"
    # vote number (i.e. seq id)
    current_vote = 0
    # block vote started at 
    current_vote_start = 0
    # vote status open(True)/closed(False)
    vote_live = False
    oracle_move = False
    # the identifier for the node (i.e. subscription topic)
    current_oracle = None
    # block number
    current_block = 0
    release_order = []
    broad_block_num = 0
    res_out = False
    instance = None
    public_key = None

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
            return True
        return False

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
        if self.public_key:
            return self.public_key
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

    def make_first_block(self):
        key = RSA.importKey(open(self.master_file, "rb").read())
        blk = block(0, 0, "base_block", self.public_key)
        blk.create_hash(key.export_key())
        # self.blocks.append(blk)
        return blk

    def extract_block(self, block_data):
        # log.info block_data
        log.info("Extracting")
        index = self.extract_field("index", block_data)
        prev_signed = self.extract_field("prev_signed", block_data)
        timestamp = self.extract_field("timestamp", block_data)
        data = self.extract_field("data", block_data)
        public_key = self.extract_field("public_key", block_data)
        signed = self.extract_field("signature", block_data)
        # log.info "extracted values for block", index, prev_signed, timestamp, signed
        return block(index, prev_signed, data, public_key, time_st=timestamp,
                     signed=signed)

    def extract_list_blocks(self, data):
        log.info("EXTRACTING LIST")
        # log.info data
        data_split = data.split(',')
        for obj in data_split:
            blk = self.extract_block(obj)
            if self.verify_block(blk):
                self.consume(blk)
        return True

    def extract_field(self, field_name, data):
        sp_data = str(data).split(';')
        for line in sp_data:
            if field_name in line:
                # log.info field_name, line
                res = line.split(': ')[-1]
                # log.info res
                return res

    def oracle(self, payload):
        zmq = ZMQ_Soc.get_instance()
        action, value = payload.split('|_|')
        if action == 'new':
            # value should be public key
            log.info('new oracle %s', value)
            if zmq.find_in_list(value):
                self.set_current_oracle(value)
                if self.public_key == value:
                    log.info('I am oracle now')
                    # send out i am
                    block = self.gen_block('oracle', f'I am oracle|_|{self.public_key}')
                    zmq.broadcast(str(block))
            # update the new oracle topic
            return True
        elif action == 'I am oracle':
            log.info('looking for oracle, broadcasters last known: %s', value)
            log.info('current oracle: %s', self.get_current_oracle())
            self.current_oracle = value
            # else:
            #     log.error('Have different oracle on record: %s',
            #               self.current_oracle)
            return True
            # check if I have been select
            # if i was selected send I am oracle out
            # 
        log.error("oracle filter not found %s", (action, value))
        return False

    def data(self, payload):
        action, value = payload.split('|_|')
        log.info("data %s", (action, value))
        return True

    def send_stub(self):
        zmq = ZMQ_Soc.get_instance()
        record = zmq.find_in_list(self.current_oracle)
        payload = {}
        payload['p_key'] = self.public_key
        res = requests.post(f'http://{record.get("connect")}:9999/stub',
                            headers={'Content-Type': 'application/json'},
                            data=json.dumps(payload))
        if res.status_code > 300:
            return False
        return True

    def vote(self, payload):
        action, value = payload.split('|_|')
        if action == 'open':
            vote_num, start_block = value.split('_|_')
            log.info(f'vote open {vote_num} {start_block}')
            self.set_current_vote(int(vote_num))
            self.set_vote_live(True)
            self.set_vote_start_block(start_block)
            # check if I have something and I am not oracle
            # if bq.queue_size() > 0:
            self.send_stub()
            return True
        elif action == 'closed':
            vote_num, start_block = value.split('_|_')
            log.info('close vote')
            self.vote_live = False
            # value is vote number
            # process results and send
            return True
            # vote status changed to closed
        elif action == 'results':
            log.info(f'results from vote {value}')
            vote_num, res_list = value.split('_|_')
            broad_list = json.loads(res_list)
            return self.process_results(broad_list)
            # vote results replace current broadcast
            # if something sent, check for my number
        log.error("vote filter not found %s", (action, value))
        return False

    def process_results(self, results):
        # get my block index from the list, if have one
        log.info(f'got results for vote: {self.current_vote} {results}')
        for index, entry in enumerate(results):
            if entry == self.public_key:
                log.info('found my slot')
                self.broad_block_num = self.current_vote_start + 1 + index
                return True
        return False

    def reg_user(self, payload):
        zmq_soc = ZMQ_Soc.get_instance()
        action, value = payload.split('|_|')
        topic, ip, pkey = value.split('_|_')
        if action == 'hello':
            log.info('new user')
            return zmq_soc.add_subscription(ip, topic, pkey)
        elif action == 'bad':
            log.info('bad user')
            return True
        elif action == 'bye':
            log.info('user leaving')
            return True
        log.error("register not found %s", (action, value))
        return False

    def vote_status(self, status):
        # check if oracle 
        # send open/close status for a vote
        # if open increment vote 
        vote_num = self.current_vote
        if status == 'open':
            vote_num = int(self.current_vote) + 1
        self.broadcast_block('vote', f'{status}|_|{vote_num}_|_{self.current_block}')

    def broad_results(self, results):
        self.broadcast_block('vote', f'results|_|{self.current_vote}_|_{str(results)}')

    def broadcast_block(self, sub_filter, payload):
        zmq_obj = ZMQ_Soc.get_instance()
        # bq = BlockQueue.get_instance()
        gen_block = self.gen_block(f'{sub_filter}', f'{payload}')
        # bq.add_block(str(gen_block))
        zmq_obj.broadcast(str(gen_block))

    def broad_block_queue(self):
        zmq_obj = ZMQ_Soc.get_instance()
        block = BlockQueue.get_instance().pop_block()
        zmq_obj.broadcast(str(block))

    def consume(self, block):
        bc = blockChain.get_instance()
        data = block.data
        fltr, payload = data.split('|_#_|')
        if fltr == 'oracle':
            if bc.add_block(block):
                self.oracle(payload)
        elif fltr == 'data':
            if bc.add_block(block):
                self.data(payload)
        elif fltr == 'vote':
            if bc.add_block(block):
                self.vote(payload)
        elif fltr == 'register':
            if bc.add_block(block):
                self.reg_user(payload)
        else:
            log.error('dropping packet unknown action: %s', fltr)
            return False
        return True

    def get_current_vote(self):
        return self.current_vote

    def set_current_vote(self, vote_num):
        self.current_vote = int(vote_num)
    
    def get_vote_start_block(self):
        return self.current_vote_start

    def set_vote_start_block(self, new_block):
        self.current_vote_start = new_block

    def get_vote_live(self):
        return self.vote_live

    def set_vote_live(self, status):
        log.info(f'setting vote {status}')
        self.vote_live = status

    def get_current_oracle(self):
        return self.current_oracle

    def set_current_oracle(self, oracle):
        self.current_oracle = oracle

    def get_current_block(self):
        return self.current_block

    def set_current_block(self, block_num):
        self.current_block = block_num
