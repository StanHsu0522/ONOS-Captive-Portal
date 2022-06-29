from flask import Flask, redirect

import os

app = Flask(__name__)

@app.route('/')
def hello():
    return redirect('https://192.168.44.198:5001/login')

if __name__ == '__main__':
    app.run(host="192.168.44.128", port=5000)