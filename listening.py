from state_machine import ZMQ_Soc, BlockQueue
import logging
import random
import time
import requests
from blockchain import blockChain
import block_args as args
import json
import threading


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
    # log.info(res.text)
    bc.extract_list_blocks(res.text)


def first_man():
    bc = blockChain.get_instance()
    blk2 = bc.gen_block('register', f'hello|_|{args.my_topic}_|_{args.my_ip}_|_{bc.get_key_pair()}')
    log.info('registering')
    if bc.verify_block(blk2):
        bc.consume(blk2)
    blk3 = bc.gen_block('oracle', f'new|_|{bc.public_key}')
    if bc.verify_block(blk3):
        bc.consume(blk3)


def get_index_release():
    bc = blockChain.get_instance()
    if not bc.vote_live and int(bc.current_vote) > 0:
        for index, entry in enumerate(bc.release_order):
            if entry == bc.public_key:
                return index + bc.current_block + 1
    return False


def my_block_next():
    bc = blockChain.get_instance()
    if int(bc.current_block) + 1 == int(bc.broad_block_num):
        # it is my turn broadcast it
        return True
    return False


def i_am_oracle():
    bc = blockChain.get_instance()
    if bc.current_oracle == bc.public_key:
        return True
    return False


def all_prev_vote_blocks_recvd():
    bc = blockChain.get_instance()
    if bc.current_block == bc.vote_start_block + len(bc.release_order):
        return True
    return False


def pick_new_oracle():
    log.info('picking new oracle')
    zmq = ZMQ_Soc.get_instance()
    bc = blockChain.get_instance()
    res = False
    # while(not res):
    res = random.choice(zmq.sub_list)
    # if args.my_ip not in res.get('connect'):
    #     log.info('got oracles')
    #     p_key = res.get('p_key')
    # else:
    #     log.info('bad oracles')
    #     res = False
    log.info('new oracle found')
    block = bc.gen_block('oracle', f'new|_|{res.get("p_key")}')
    zmq.broadcast(str(block))


def countdown(delay):
    log.info('running vote closed now')
    bc = blockChain.get_instance()
    time.sleep(delay)
    bc.vote_status('closed')


def oracle_action():
    bc = blockChain.get_instance()
    zmq = ZMQ_Soc.get_instance()
    if len(zmq.sub_list) > 0:
        if not bc.vote_live and not bc.oracle_move:
            log.info('in vote not live')
            bc.vote_status('open')
            bc.oracle_move = True
            # create vote open block with my ip and min open time
            # as oracle wait for min open time to finish
            # send close_vote
            threading.Thread(target=countdown, args=(5,)).start()
            # time.sleep(5)
            # bc.vote_status('closed')
            # consume all stubs, create release order
            # send release_order   
            return
        elif bc.oracle_move and not bc.vote_live:
            log.info(f'in vote broadcast {bc.release_order}')
            if bc.release_order:
                log.info('in release order')
                random.shuffle(bc.release_order)
                bc.broad_results(bc.release_order)
            else:
                log.info('in list only')
                bc.broad_results([])
            bc.res_out = True
            bc.oracle_move = False
            return
        elif bc.res_out:
            if all_prev_vote_blocks_recvd():
                log.info('in vote oracle')
                # choose new oracle (New Oracle is XXX.XXX.XXX.XXX)
                # needs to happen after

                pick_new_oracle()
                bc.res_out = False
                bc.oracle_move = False
                bc.vote_live = False
            return


def next_move():
    # grab state machine, and blockchain
    bc = blockChain.get_instance()
    if my_block_next():
        log.info('Its my turn, sending...')
        bc.broad_block_queue()
    elif i_am_oracle():
        log.info('Oracle action check')
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
            log.info('making next move')
            next_move()
        # if my block is next on receipt send out block
        # Or if I am oracle and I HAVE Peers 
        # Or if I am oracle and I HAVE Peers and final  vote closed and final release block recv
        else:
            log.error('block dropped: %s', blk.index)
