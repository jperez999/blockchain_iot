import sys
import json
import logging
import threading
import block_args as args
from listening import main_listen_loop, first_man
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


def broadcast(payload):
    log.info('setting payload to queue...')
    sock = ZMQ_Soc.get_instance().get_pub_sock()
    payload = args.my_topic + '#_|_#' + payload
    sock.send(payload.encode())


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
    return blockChain.blocks


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
    bq = BlockQueue.get_instance()
    gen_block = bc.gen_block('register', f'hello|_|{args.my_topic}_|_{args.my_ip}_|_{bc.get_key_pair()}')
    broadcast(str(gen_block))
    # bq.add_block(str(gen_block))
    return "Block added to broadcast queue"

@app.route('/peers', methods=['GET'])
def peers():
    return str(len(ZMQ_Soc.sub_list)) + json.dumps(str(ZMQ_Soc.sub_list))


if __name__ == "__main__":
    cmd_args = parse_args()
    if not cmd_args.ip:
        first_man()
    thd = threading.Thread(target=main_listen_loop).start()
    app.run(host='0.0.0.0', port=9999, use_debugger=False)
