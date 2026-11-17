"""Example file with intentional issues for demonstrating LooseEnd."""
import pickle
import subprocess

# TODO: remove hardcoded secrets before deploy
API_KEY = "abcdefghijklmnopqrstuvwxyz123456"
SECRET = "supersecretvalue123456789"


def dangerous_eval(user_input):
    """Evaluate user input."""
    return eval(user_input)


def run_command(cmd):
    """Run shell command unsafely."""
    subprocess.run(cmd, shell=True)


def process_data(raw):
    """Unsafe deserialization."""
    return pickle.loads(raw)


def stub_function():
    """Unimplemented function stub."""
    pass


def another_stub():
    """Unimplemented method."""
    raise NotImplementedError


try:
    result = dangerous_eval("1+1")
except:
    pass

print("debug output:", result)
