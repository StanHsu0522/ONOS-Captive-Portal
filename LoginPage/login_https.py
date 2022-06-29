from flask import Flask, request, render_template, redirect, url_for
import os

app = Flask(__name__)

@app.route('/')
def hello():
    return redirect('https://192.168.44.198:5001/login')


@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST': 
        account = request.values['user_name']
        password = request.values['user_password']
        cmdExec = "curl -X POST http://192.168.44.128:8181/RadiusAuthentication/UserCredential -u onos:rocks -d " + "'user=" +\
             account + "&" +"pass=" + password + "'"
        f = os.popen(cmdExec)
        result = f.read()
        if result=='Access-Accept':
            cmdExec = "curl -X POST http://192.168.44.128:8181/RadiusAuthentication/UserCredential/insertNewUser -u onos:rocks -d 'ip=" +request.remote_addr+"'"
            f=os.popen(cmdExec)
            is_insert = f.read()
            if is_insert == '0':
                print("insert success")
                return redirect('https://www.nctu.edu.tw')
            else:
                cmdExec = "curl -X POST http://192.168.44.128:8181/RadiusAuthentication/UserCredential/getUser -u onos:rocks -d 'ip="+request.remote_addr+"'"
                f=os.popen(cmdExec)
                is_user = f.read()
                if is_user == 'true':
                    print("get success")
                    return redirect('https://www.nctu.edu.tw')
                print("insert failed")
        return redirect('https://192.168.44.198:5001/fail')

    return render_template('index.html')

@app.route('/fail', methods=['GET','POST'])
def fail():
    if request.method == 'POST':
        return redirect('https://192.168.44.198:5001/login')
    return render_template('login_failed.html')


if __name__ == '__main__':
    # app.debug = True
    app.run(host="192.168.44.128",port=5001, ssl_context=("adhoc"))
