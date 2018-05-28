import time
import socket
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pss
import sys
import threading


class block(object):

    def __init__(self, index, previous_signed,  data, public_key, time_st=time.clock(), signed=None):
        self.index = index
        self.prev_signed = previous_signed
        self.timestamp = time_st
        self.data = data
        self.public_key = public_key
        self.signed = signed
        
        
    def create_hash(self, private_key):
        print "in block hash function..."
        key = RSA.importKey(private_key.encode())
        if self.signed != None:
            return self.signed
        print "making the HMAC for block"
        payload = str(self.index) + "_:_" + str(self.prev_signed) + "_:_" + str(self.data)
        signer = SHA256.new(payload)
        # create signature using index, data, previous_hash and private key
        # signer.update(payload.encode())
        self.signed = pss.new(key).sign(signer)

    def __repr__(self):
        return '{\n\n "index": ' + str(self.index) + '\n\n"prev_signed": ' + str(self.prev_signed) + '\n\n "timestamp": ' + str(self.timestamp) + '\n\n"data": ' + str(self.data) + '\n\n"public_key": ' + str(self.public_key) + '\n\n"signature": ' + str(self.signed) + "\n\n}\n\n"  


class blockChain(object):
    blocks = []
    peers = []
    master_file = "blockchain_key.pem"
    bc_k_file = "user_bc_key.pem"
    udp_server_address = ('localhost', 10000)
    tcp_server_address = ('localhost', 9999)

    def __init__(self):
        #------------SERVERS INIT START-------------------
        self.sock_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        udp = threading.Thread(target=self.udp_server)
        tcp = threading.Thread(target=self.tcp_server)
        udp.start()
        tcp.start() 
        #-----------SERVER INIT COMPLETE -----------------
        self.blocks.append(self.make_first_block())
        self.run()
        
    def refresh_blocks(self, blocks):
        print "REFRESH BLOCKS"
        # ask other peers for their chains
        #self.blocks = blocks
        # compare response to your
        # take most current
        pass


    def gen_block(self, data):
        print self.blocks
        blk =  block(self.blocks[-1].index + 1, self.blocks[-1].signed, data, self.public_key)
        print "signing block"
        blk.create_hash(self.private_key)
        print "block is ready", blk
        self.send_block(blk)

    def send_block(self, block):
        print "Following block about to go out:", block
        sent = self.sock_udp.sendto("add_=_" + str(block), self.udp_server_address)
        return sent

    def verify_block(self, block):
        print "VERIFYING", block
        key = RSA.importKey(block.public_key.encode())
        # TODO create_hash for block
        payload = str(block.index) + "_:_" + str(block.prev_signed) + "_:_" + str(block.data)
        hasher = SHA256.new(payload)
        v = pss.new(key.publickey())
        try:
            v.verify(hasher, block.signed)
            print "VERIFY Success"
        except:
            print "FAILED Verify"
            # compare to block hash
            # add block
        

    def get_peers(self):
        self.sock_udp.sendto("peers_=_request", self.udp_server_address)
        return

    def verify_peer(self, public_key):
        print "verifying key..."
        if public_key == None:
            print "key not found"
            return False
        if public_key in self.peers:
            print "verification complete"
            return True
        print "adding key to peers list"
        self.register()
        return True 
        

    def gen_blockchain_key(self):
        key = RSA.generate(2048)
        self.private_key = key.export_key('PEM')
        self.public_key  = key.publickey().export_key()
        prK_file = open(self.bc_k_file, "w")
        prK_file.write(self.private_key)
        prK_file.close()
        return self.public_key

    def get_key_pair(self):
        print "Looking for keys"
        try:
            encoded_key = open(self.bc_k_file, "r").read()
            key = RSA.import_key(encoded_key)
            self.public_key = key.publickey().export_key()
            self.private_key = key.export_key()
            print "Key found!"
            return True
        except:
            print "Failed to get keys, creating..."
            self.gen_blockchain_key()
            return False

    def register(self):
        #self.get_peers()
        # send out registration block
        print "creating registration block"
        self.gen_block("register_#_" + self.public_key)
        return True

    def make_first_block(self):
        key = RSA.importKey(open(self.master_file, "rb").read())
        blk = block(0, 0, "base_block", key.publickey().export_key())
        blk.create_hash(key.export_key())
        #self.blocks.append(blk)
        return blk

    def extract_block(self, block_data):
        print "EXTRACT"
        #print block_data
        index = self.extract_field("index", block_data)
        prev_signed = self.extract_field("prev_signed", block_data) 
        timestamp = self.extract_field("timestamp", block_data)
        data = self.extract_field("data", block_data)
        public_key = self.extract_field("public_key", block_data)
        signed = self.extract_field("signature", block_data)
        print "extracted values for block", index, prev_signed, timestamp, signed
        return block(index, prev_signed, data, public_key, time_st=timestamp, signed=signed)
         

    def extract_list_blocks(self):
        pass

    def extract_field(self, field_name, data):
        sp_data = data.split('\n\n')
        for line in sp_data:
            if field_name in line:
                #print field_name, line
                res = line.split (': ')[-1]
                #print res
                return res

    def join(self):
        print "Joining the network..."
        if not self.get_key_pair():
            print "Couldn't find your keys"
            self.register()
            print "register complete in join"
            self.get_peers()
            print "peers list complete in join"
            self.refresh_blocks()
            print "refresh blocks complete in join"
        if self.verify_peer(self.public_key):
            print "Found keys, verify OK!"
            return True
        return False

    def run(self):
       #add join logic
        self.join()
        #update block chain
        #turn on blockchain
        pass


    def udp_server(self):
        print >>sys.stderr, 'starting up on %s port %s' % self.udp_server_address
        self.sock_udp.bind(self.udp_server_address)
        while True:
            print >> sys.stderr, '\nwaiting to receive message'
            data_udp, address_udp = self.sock_udp.recvfrom(4096)

            print >> sys.stderr, 'received %s bytes from %s' % (len(data_udp), address_udp)
            print "UDP data ---> ", data_udp 
            data_set = data_udp.split('_=_')
            if data_set[0] == "add": 
                #split up string and contain each field
                blk = self.extract_block(data_set[1])
                #create block from data
                #verify block
                self.verify_block(blk)
                #add block to blockchain
                #sent = self.sock.sendto(data, address)
                #print "inside add", data_set
                

	    if data_set[0] == "register":
                print "New member joining..."
                self.peers.append(data_set[1])
                print "new peer: " , self.peers[-1]

	    if data_set[0] == "blocks":
                print "received blocks request, sending blocks..."
                self.sock_udp.sendto("list_blocks_=_" + str(self.blocks), address_udp)

            if data_set[0] == "peers":
                print "received peer request, sending list..."
                self.sock_udp.sendto("list_peers_=_" + str(self.peers),address_udp) 

	
    def tcp_server(self):
        print >>sys.stderr, 'starting up on %s port %s' % self.tcp_server_address
        self.sock_tcp.bind(self.tcp_server_address)
        self.sock_tcp.listen(2)
        while True:
            print >> sys.stderr, '\nwaiting to receive message'
            conn, address_tcp = self.sock_tcp.accept()
            data_tcp = conn.recv(4096).decode("ascii")               
            print data_tcp
            data = data_tcp.split('_=_')
            if data[0] == "add":
                print "data to add", data[1]
                block_to_send = self.gen_block(data[1])
                sent = self.send_block(block_to_send)
                print "sent block size of:", str(sent)
            if data[1] == "blocks":
                print self.blocks
            

       

alpha = blockChain()
