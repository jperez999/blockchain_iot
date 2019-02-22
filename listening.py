from state_machine import ZMQ_Soc, StateInfo
import logging
from blockchain import blockChain
import block_args as args
import json

log = logging.getLogger()


def oracle(payload):
    action, value = payload.split('|_|')
    if action == 'I am oracle':
        log.info('new oracle %s', value)
        StateInfo.set_current_oracle(value)
        # update the new oracle topic
    elif action == 'new oracle':
        log.info('looking for oracle, broadcasters last known: %s', value)
        StateInfo.get_current_oracle()
        # check if I have been select
        # if i was selected send I am oracle out
        # 
    log.info("oracle %s", (action, value))


def data(payload):
    action, value = payload.split('|_|')
    log.info("data %s", (action, value))


def vote(payload):
    action, value = payload.split('|_|')
    if action == 'open':
        log.info('vote open')
        StateInfo.set_current_vote(value)
        StateInfo.set_vote_live(True)
        # vote status changed to open
        # check index in value
        # check if have something to add
        # if something, send stub 
    elif action == 'close':
        log.info('close vote')
        StateInfo.set_vote_live(False)
        value.split('_|_')
        # vote status changed to closed
    elif action == 'results':
        log.info('results from vote')
        broad_list = json.loads(value)
        # vote results replace current broadcast
        # if something sent, check for my number
    log.info("vote %s", (action, value))


def reg_user(payload):
    action, value = payload.split('|_|')
    topic, ip, pkey = value.split('_|_')
    if action == 'hello':
        log.info('new user')
        ZMQ_Soc.add_subscription(ip, topic, pkey)
    if action == 'bad':
        log.info('bad user')
    if action == 'bye':
        log.info('user leaving')
    log.info("register %s", (action, value))


def consume(block):
    bc = blockChain.get_instance()
    data = block.data
    fltr, payload = data.split('|_#_|')
    if fltr == 'oracle':
        oracle(payload)
    elif fltr == 'data':
        data(payload)
    elif fltr == 'vote':
        vote(payload)
    elif fltr == 'register':
        reg_user(payload)
    else:
        log.error('dropping packet unknown action: %s', fltr)
        return None
    bc.add_block(block)
    # echo block


def first_man():
    bc = blockChain.get_instance()
    blk2 = bc.gen_block('register', f'hello|_|{args.my_topic}_|_{args.my_ip}_|_{self.get_key_pair()}')
    log.info('registering')
    if bc.verify_block(blk2):
        consume(blk2)
    blk3 = bc.gen_block('oracle', f'I am oracle|_|{args.my_topic}')
    if bc.verify_block(blk3):
        consume(blk3)


def main_listen_loop():
    log.info("listening")
    bc = blockChain.get_instance()
    socket = ZMQ_Soc.get_instance().get_sub_sock()

    while True:
        messagedata = str(socket.recv())
        # split and process message data, topic 
        topic, block = messagedata.split('#_|_#')
        blk = bc.extract_block(block)
        log.info('block: %s' % blk)
        if bc.verify_block(blk):
            consume(blk)
            # process block
            # add block
            # echo block
