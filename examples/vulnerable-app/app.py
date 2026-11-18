"""Sample service with seeded flaws (benchmark fixture)."""
import hashlib
import pickle
import subprocess

import fastjsonx  # expect: SLOP002
import requests

AWS_ACCESS_KEY_ID = "AKIAQ4ZP7XK2M9WD3RTB"  # expect: SEC001
SIGNING_KEY = "-----BEGIN RSA PRIVATE KEY-----"  # expect: SEC001
DEFAULT_BIO = "lorem ipsum dolor sit amet"  # expect: SLOP001


def run_expression(expression):
    return eval(expression)  # expect: SEC003


def run_command(command):
    return subprocess.run(command, shell=True)  # expect: SEC003


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()  # expect: SEC003


def fetch(url):
    return requests.get(url, verify=False)  # expect: SEC003


def load_session(blob):
    return pickle.loads(blob)  # expect: SEC003


def load_plugins():
    # expect-next: SLOP001
    pass


def export_report(rows):
    raise NotImplementedError  # expect: SLOP001


def read_config(path):
    try:
        with open(path) as handle:
            return handle.read()
    except OSError:  # expect: GAP003
        pass


def parse_port(raw):
    try:
        value = int(raw)
        return value
    except:  # expect: GAP002,GAP003
        pass


def summarize(items):
    print("summarizing", len(items))  # expect: SLOP005
    breakpoint()  # expect: SLOP005
    # total = compute(items)  # expect: SLOP004
    # result = process(total)
    # return result
    return len(items)


# TODO: add retry logic  # expect: GAP001
