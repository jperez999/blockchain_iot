from state_machine import ZMQ_Soc
import logging
import requests
from blockchain import blockChain
import block_args as args
import json

log = logging.getLogger()


def join_up(node_ip):
    bc = blockChain.get_instance()
    endpoint = f'http://{node_ip}:9999/join'
    payload = {
        'con_str': args.my_ip,
        'topic': args.my_topic,
        'p_key': bc.get_key_pair()
    }
    res = requests.post(endpoint,
                        headers={'Content-Type': 'application/json'},
                        data=json.dumps(payload))
    log.info(res.test)
    bc.extract_list_blocks(res.text)


def first_man():
    bc = blockChain.get_instance()
    blk2 = bc.gen_block('register', f'hello|_|{args.my_topic}_|_{args.my_ip}_|_{bc.get_key_pair()}')
    log.info('registering')
    if bc.verify_block(blk2):
        bc.consume(blk2)
    blk3 = bc.gen_block('oracle', f'I am oracle|_|{args.my_topic}')
    if bc.verify_block(blk3):
        bc.consume(blk3)


def main_listen_loop():
    log.info("listening")
    bc = blockChain.get_instance()
    log.info('blockchain in')
    zmq_obj = ZMQ_Soc.get_instance()
    log.info('zmq instance in')
    socket = zmq_obj.get_sub_sock()
    log.info('socket grabbed')
    while True:
        messagedata = str(socket.recv())
        # split and process message data, topic 
        topic, block = messagedata.split('#_|_#')
        blk = bc.extract_block(block)
        if int(blk.index) == len(bc.blocks) and bc.verify_block(blk):
            if bc.consume(blk):
                zmq_obj.broadcast(block)
            # process block
            # add block
            # echo block
        else:
            log.error('block dropped: %s', blk.index)
