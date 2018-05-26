import time
import socket
from Crypto.PublicKey import RSA
from Crypto.Hash import HMAC
import sys
import threading


class block(object):

    def __init__(self, index, previous_signed, data, public_key, private_key):
        self.index = index
        self.prev_signed = previous_signed
        self.timestamp = time.clock()
        self.data = data
        self.public_key = public_key
        self.signed = self.create_hash(index, previous_signed, data, private_key)

    def create_hash(self, index, prev_signature, data, private_key):
        print "making the HMAC for block"
        signer = HMAC.new(private_key)
        # create signature using index, data, previous_hash and private key
        payload = str(index) + "-" + str(prev_signature) + "-" + str(data)
        signer.update(payload)
        return signer.hexdigest()

    def __repr__(self):
        return str(self.index) + " - " + str(self.prev_signed) + " - " + str(self.timestamp) + " - " + str(self.data) + " - " + str(self.public_key) + " - " + str(self.signed)  


class blockChain(object):
    blocks = []
    peers = []
    bc_k_file = "blockchain_key.pem"
    udp_server_address = ('localhost', 10000)
    tcp_server_address = ('localhost', 9999)

    def __init__(self):
        self.sock_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #self.blocks = self.make_first_block()
        self.run()
        
    def refresh_blocks(self, blocks):
        # ask other peers for their chains
        self.blocks = blocks
        # compare response to your
        # take most current
        pass


    def gen_block(self, data):
        blk =  block(self.blocks[-1].index + 1, self.blocks[-1].prev_signed, data, self.public_key, self.private_key)
        print "making new block", blk
        self.blocks.append(blk)
        return blk

    def send_block(self, block):
        print "Following block about to go out:", block
        sent = self.sock_udp.sendto(str(block), self.udp_server_address)
        print "block sent:",sent

    def verify_block(self, block):
        # TODO create_hash for block
        # compare to block hash
        # add block
        pass

    def get_peers(self):
        self.peers.append(self.public_key)
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
        self.peers.append(public_key)
        return True 
        

    def gen_blockchain_key(self):
        key = RSA.generate(2048)
        private_key = key.export_key('PEM')
        public_key  = key.publickey().export_key()
        prK_file = open(self.bc_k_file, "w")
        prK_file.write(private_key)
        prK_file.close()
        return public_key

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
            print "Failed to get keys"
            return False

    def register(self):
        self.get_peers()
        # send out registration block
        print "sending registration"
        self.gen_block("Registration Request - ", self.public_key)
        return True

    def make_first_block(self):
        blk = block(0, 0, "base_block", self.public_key, self.private_key)
        self.blocks.append(blk)
        return True


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
	self.make_first_block()
        #update block chain
        #turn on blockchain
        udp = threading.Thread(target=self.udp_server)
        tcp = threading.Thread(target=self.tcp_server)
        udp.start()
        tcp.start()
        pass


    def udp_server(self):
        print >>sys.stderr, 'starting up on %s port %s' % self.udp_server_address
        self.sock_udp.bind(self.udp_server_address)
        while True:
            print >> sys.stderr, '\nwaiting to receive message'
            data_udp, address_udp = self.sock_udp.recvfrom(4096)

            print >> sys.stderr, 'received %s bytes from %s' % (len(data_udp), address_udp)
             
            data_set = data_udp.split('-')
            if data_set[0] == "add - "" ":
                
                #sent = self.sock.sendto(data, address)
                print "inside add", data_set

	    if data_set[0] == "register":
                print "inside register", data_set
                self.peers.append(data_set[1])
                print self.peers

	    if data_set[0] == "blocks":
                print self.blocks

	
    def tcp_server(self):
        print >>sys.stderr, 'starting up on %s port %s' % self.tcp_server_address
        self.sock_tcp.bind(self.tcp_server_address)
        self.sock_tcp.listen(2)
        while True:
            print >> sys.stderr, '\nwaiting to receive message'
            conn, address_tcp = self.sock_tcp.accept()
            data_tcp = conn.recv(4096).decode("ascii")               
            print data_tcp
            data = data_tcp.split('-')
            if data[0] == "add":
                print "data to add", data[1]
                block_to_send = self.gen_block(data[1])
                self.send_block(block_to_send)
            

       

alpha = blockChain()
