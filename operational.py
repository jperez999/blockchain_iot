import sys
import json
import time
import logging
import threading
import block_args as args
from listening import main_listen_loop, first_man, join_up
from flask import Flask, request
from state_machine import ZMQ_Soc, BlockQueue
from blockchain import blockChain
from argparse import ArgumentParser

logFormatter = logging.Formatter('%(asctime)s] p%(process)s {%(pathname)s:%(lineno)d} - %(message)s','%m-%d %H:%M:%S')
log = logging.getLogger()
fileHandler = logging.FileHandler("{}.log".format('block'))
fileHandler.setFormatter(logFormatter)
log.addHandler(fileHandler)
consoleHandler = logging.StreamHandler()
consoleHandler.setFormatter(logFormatter)
log.addHandler(consoleHandler)
log.setLevel(logging.INFO)


def parse_args():
    parser = ArgumentParser()
    parser.add_argument('--node-ip', default=None)
    return parser.parse_args()


def broadcast_block(sub_filter, payload):
    bc = blockChain.get_instance()
    # zmq_obj = ZMQ_Soc.get_instance()
    bq = BlockQueue.get_instance()
    gen_block = bc.gen_block(f'{sub_filter}', f'{payload}')
    bq.add_block(str(gen_block))
    # zmq_obj.broadcast(str(gen_block))


def reg_api(con_str, topic, p_key, sub_filter='hello'):
    time.sleep(2)
    broadcast_block('register',
                    f'{sub_filter}|_|{topic}_|_{con_str}_|_{p_key}')
    return True


def oracle_api(payload, iam=False):
    if not i_am_oracle():
        return False
    req = f'oracle is|_|{payload}'
    if iam:
        req = f'I am oracle|_|{payload}'
    broadcast_block('oracle', req)
    return True


def i_am_oracle():
    bc = blockChain.get_instance()
    return bc.current_oracle == args.my_topic


app = Flask(__name__)
app.debug = False


@app.route('/blocks', methods=['POST'])
def blocks():
    return str(blockChain.blocks)


@app.route('/join', methods=['POST'])
def join():
    # take info 
    data = request.json
    log.info(data)
    threading.Thread(target=reg_api, 
                     args=(data['con_str'], data['topic'], data['p_key'])).start()
    return str(blockChain.blocks)


# @app.route('/send_data', methods=['POST'])
# def send_post_data():
#     data = request.json
#     broadcast(data['payload'])
#     return True


@app.route('/send_data', methods=['GET'])
def send_get_data():
    # create block
    # send block
    bc = blockChain.get_instance()
    # zmq_obj = ZMQ_Soc.get_instance()
    bq = BlockQueue.get_instance()
    gen_block = bc.gen_block('register', f'hello|_|{args.my_topic}_|_{args.my_ip}_|_{bc.get_key_pair()}')
    bq.add_block(str(gen_block))
    # zmq_obj.broadcast(str(gen_block))
    return "Block added to broadcast queue"


@app.route('/peers', methods=['GET'])
def peers():
    return str(len(ZMQ_Soc.sub_list)) + json.dumps(str(ZMQ_Soc.sub_list))


# p_key=<p_key>
@app.route('/stubs', methods=['POST'])
def stubs():
    data = request.get_json()
    log.info(f'stubs req: {data}')
    zmq = ZMQ_Soc.get_instance()
    bc = blockChain.get_instance()
    if zmq.find_in_list(data.get('p_key')):
        if data.get('p_key') not in zmq.stubs_list:
            log.info('adding key to release')
            bc.release_order.append(data.get('p_key'))
            return json.dumps({}), 200
        else:
            return json.dumps({'error': 'already has a slot'}), 405
    else:
        return json.dumps({'error': 'peer not found'}), 406


if __name__ == "__main__":
    cmd_args = parse_args()
    bc = blockChain.get_instance()
    ZMQ_Soc.get_instance().add_subscription(args.my_ip, args.my_topic, bc.public_key)
    log.info(cmd_args)
    if cmd_args.node_ip:
        join_up(cmd_args.node_ip)
    else:
        first_man()
    thd = threading.Thread(target=main_listen_loop).start()
    app.run(host='0.0.0.0', port=9999, use_debugger=False)
