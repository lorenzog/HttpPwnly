import uuid


class SessionAuthenticator(object):
    def __init__(self):
        # make a dictionary for multiple users: {'username': sid}
        self.storage = []

    def validate(self, sid):
        if sid is None:
            return False
        if sid not in self.storage:
            return False
        # it's a valid session
        return True

    def new_session(self):
        sid = str(uuid.uuid4())
        self.storage.append(sid)
        return sid
