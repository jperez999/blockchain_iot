import logging
import os
import requests


log = logging.getLogger()

port = 5559


def get_my_ip():
    if os.environ.get('USER') == 'ec2-user':
        return requests.get(os.environ.get('_'))
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    res = s.getsockname()[0]
    log.info(res)
    s.close()
    return res


my_ip = get_my_ip()
my_topic = f"{my_ip}TOPIC"