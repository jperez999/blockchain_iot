import sys
import zmq
import block_args as args
import logging
import queue
from blockchain import blockChain

log = logging.getLogger()


class ZMQ_Soc:
    # Socket to talk to server
    context = zmq.Context()
    sub_list = []
    sub_socket = None
    pub_socket = None
    instance = None

    def __init__(self):
        if ZMQ_Soc.instance:
            log.info('this is a singleton')
        else:
            ZMQ_Soc.instance = self
            ZMQ_Soc.get_pub_sock(self)
            ZMQ_Soc.get_sub_sock(self)

    @staticmethod
    def get_instance():
        if not ZMQ_Soc.instance:
            ZMQ_Soc()
        return ZMQ_Soc.instance

    def get_sub_sock(self):
        if not self.sub_socket:
            self.sub_socket = self.context.socket(zmq.SUB)
            self.add_subscription(args.my_ip, args.my_topic, blockChain().get_key_pair())
        return self.sub_socket

    def get_pub_sock(self):
        if not self.pub_socket:
            self.pub_socket = self.context.socket(zmq.PUB)
            self.pub_socket.bind("tcp://*:%s" % args.port)
        return self.pub_socket

    def add_subscription(self, con_str, topic, p_key):
        self.sub_socket.connect("tcp://%s:%s" % (con_str, args.port))
        self.sub_socket.setsockopt(zmq.SUBSCRIBE, topic.encode())
        self.sub_list.append(self.create_sub_tuple(con_str, topic, p_key))
        log.info('added this ip %s', (con_str, args.port, topic))

    def create_sub_tuple(self, con_str, topic, p_key):
        req = {}
        req['connect'] = con_str
        req['topic'] = topic
        req['p_key'] = p_key
        req['status'] = "active"
        return req

    def set_tup_inactive(self, topic):
        for rec in self.sub_list:
            if rec['topic'] == topic:
                rec['status'] == 'inactive'
                self.sub_socket.setsockopt(zmq.UNSUBSCRIBE, topic)
                return True
        return False


class BlockQueue(object):
    instance = None
    block_queue = None

    def __init__(self):
        if BlockQueue.instance:
            log.info('this is a singleton')
        else:
            BlockQueue.instance = self
            self.block_queue = queue.Queue()

    @staticmethod
    def get_instance():
        if not BlockQueue.instance:
            BlockQueue()
        return BlockQueue.instance

    def add_block(self, block):
        try:
            self.block_queue.put(block)
        except queue.Full as e:
            log.error(str(e))
            return False
        return True

    def pop_block(self):
        try:
            return self.block_queue.get()
        except queue.Empty as e:
            log.error(str(e))
        return False

    def queue_size(self):
        return self.block_queue.qsize


class StateInfo(object):
    # vote number (i.e. seq id)
    current_vote = 0
    # vote status open(True)/closed(False)
    vote_live = False
    # the identifier for the node (i.e. subscription topic)
    current_oracle = None
    # block number
    current_block = 0
    instance = None

    def __init__(self):
        if StateInfo.instance:
            log.info('this is a singleton')
        else:
            StateInfo.instance = self

    @staticmethod
    def get_instance():
        if not StateInfo.instance:
            StateInfo()
        return StateInfo.instance

    def get_current_vote(self):
        return self.current_vote

    def set_current_vote(self, vote_num):
        self.current_vote = vote_num
    
    def get_vote_live(self):
        return self.vote_live

    def set_vote_live(self, status):
        self.vote_live = status

    def get_current_oracle(self):
        return self.current_oracle

    def set_current_oracle(self, oracle):
        self.current_vote = oracle

    def get_current_block(self):
        return self.current_block

    def set_current_block(self, block_num):
        self.current_block = block_num
