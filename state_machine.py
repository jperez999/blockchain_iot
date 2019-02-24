import zmq
import block_args as args
import logging
import queue

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
        return self.sub_socket

    def get_pub_sock(self):
        if not self.pub_socket:
            self.pub_socket = self.context.socket(zmq.PUB)
            self.pub_socket.bind("tcp://*:%s" % args.port)
        return self.pub_socket

    def add_subscription(self, con_str, topic, p_key):
        new_rec = self.create_sub_tuple(con_str, topic, p_key)
        if self.rec_dup_check(new_rec):
            return False
        self.sub_socket.connect("tcp://%s:%s" % (con_str, args.port))
        self.sub_socket.setsockopt(zmq.SUBSCRIBE, topic.encode())
        self.sub_list.append(new_rec)
        log.info('added this ip %s', (con_str, args.port, topic))
        return True

    def rec_dup_check(self, new_rec):
        for rec in self.sub_list:
            if new_rec['connect'] == rec['connect'] or\
               new_rec['p_key'] == rec['p_key']:
                log.info('record found!')
                return True
        return False

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

    def broadcast(self, payload):
        log.info('setting payload to queue...')
        sock = self.get_pub_sock()
        payload = args.my_topic + '#_|_#' + payload
        sock.send(payload.encode())


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


