from state_machine import ZMQ_Soc, BlockQueue
import logging
import random
import requests
from blockchain import blockChain
import block_args as args
import json
from operational import vote_status, broad_results

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
    log.info(res.text)
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


def my_block_next():
    bc = blockChain.get_instance()
    my_index = bc.release_order[args.my_ip]
    if bc.current_block + 1 == my_start_point:
        # it is my turn broadcast it
        return True
    return False


def i_am_oracle():
    bc = blockChain.get_instance()
    if bc.current_oracle == args.my_ip:
        return True
    return False


def all_prev_vote_blocks_recvd():
    if bc.current_block == bc.release_order['final_block']:
        return True
    return False


def pick_new_oracle():
    zmq = ZMQ_Soc.get_instance()
    bc = blockChain.get_instance()
    res = None
    while(not res and args.my_ip not in res['connect']):
        res = random.choice(zmq.sub_list())
    block = bc.gen_block('oracle', f'new|_|{res['p_key']}')
    zmq.broadcast(block)


def oracle_action():
    bc = blockChain.get_instance()
    zmq = ZMQ_Soc.get_instance()
    if len(zmq.sub_list) > 1:
        if not bc.vote_live:
            zmq.stubs_list = []
            vote_status('open')
            # create vote open block with my ip and min open time
            # as oracle wait for min open time to finish
            sleep(2)
            # send close_vote
            vote_status('closed')
            # consume all stubs, create release order
            # send release_order
            broad_results(random.shuffle(zmq.stubs_list))
        elif bc.vote_live and all_prev_vote_blocks_recvd(): 
            # choose new oracle (New Oracle is XXX.XXX.XXX.XXX)
            pick_new_oracle()


def next_move():
    # grab state machine, and blockchain
    bc = blockChain.get_instance()
    bq = BlockQueue.get_instance()
    zmq = ZMQ_Soc.get_instance()
    if my_block_next():
        zmq.broadcast(bq.pop_block())
    elif i_am_oracle():
        oracle_action()


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
                # process block
                # add block
            if bc.consume(blk):
                # echo block
                zmq_obj.broadcast(block)
            next_move()
        # if my block is next on receipt send out block
        # Or if I am oracle and I HAVE Peers 
        # Or if I am oracle and I HAVE Peers and final  vote closed and final release block recv
        else:
            log.error('block dropped: %s', blk.index)
