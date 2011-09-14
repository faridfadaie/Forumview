from gevent.pywsgi import WSGIServer
import facebook
import gevent.pywsgi
import time, logging, sys, json, hashlib, base64, urllib2
from simpledb import SimpleDB, SimpleDBError, AttributeEncoder

allowed_functions = ['/create_label', 'create_label', '/get_labels', 'get_labels']
page_names = ['load_group.html']
page_contents = {}
LISTEN_IP = '0.0.0.0'
LISTEN_PORT = 10000
ACTIVATION_LIMIT = 3
AV_LIMIT = -1
CODEC_LIMIT = 3
RETRY_LIMIT = 3
PROTOCOL = 'http'
FACEBOOK_KEY = '246575252046549'
FACEBOOK_SECRET = 'bba342dc751c88d7522ce822d4d30ab8'
AWS_ACCESS_KEY = 'AKIAJ36DOHUEJB4QN5WA'
AWS_SECRET_ACCESS_KEY = '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'
AWS_SDB_DOMAIN = 'test'

for i in sys.argv:
    if i.find('-proto=') != -1:
        PROTOCOL = i.split('-proto=')[1]
    if i.find('-port=') != -1:
        LISTEN_PORT = int(i.split('-port=')[1])
    if i.find('-daemon=no') != -1:
        DAEMON = False
    if i.find('-conf=') != -1:
        CONFIG_NAME = i.split('-conf=')[1]

if PROTOCOL not in ['https', 'http']:
    print "The protocol can only be http or https.\n"
    raise SystemExit 


def _load_pages():
    for i in page_names:
        f = open(i, 'r')
        page_contents[i] = f.read()
        f.close()

def load_group(name, env, start_response):
    start_response('200 OK',[])
    return [page_contents['load_group.html']]

def _validate_fb(env):
    cookies = []
    if 'HTTP_COOKIE' in env:
        cookies = env['HTTP_COOKIE']
        cookies = [(x.split('=')[0], x.strip(x.split('=')[0]+'=')) for x in cookies.split(';')]
    cookies = dict(cookies)
    user = facebook.get_user_from_cookie(cookies, FACEBOOK_KEY, FACEBOOK_SECRET)
    if user:
        graph = facebook.GraphAPI(user["access_token"])
        groups = graph.get_connections("me", "groups")
        user['groups'] = groups['data']
    return user

def _is_group_admin(gid, user):
    for i in user['groups']:
        if (i['id'] == gid) and (i.has_key('administrator')):
            return True
    return False

def _can_access(gid, user):
    graph = facebook.GraphAPI(user["access_token"])
    try:
        obj = graph.get_object("%s" %gid)
    except:
        return False
    if obj.has_key('id'):
        return True
    return False

def _load_args(env):
    method = env['REQUEST_METHOD']
    if method == 'POST':
        post_body = env['wsgi.input'].read()
        return json.loads(post_body)
    else:
        data = {}
        query = env['QUERY_STRING']
        while query.count('=') != 0:
            key = query.split('=')[0]
            value = query.split('%s=' %key)[1].split('&')[0]
            data[urllib2.unquote(key)] = urllib2.unquote(value)
            if query.count('&') != 0:
                query=query.split(key + '=' + value + '&')[1]
            else:
                query = ''
        return data

def _json_error(env, start_response, err):
    start_response('200 OK',[])
    return [json.dumps({'type': 'error', 'code' : err[0], 'reason' : err[1], 'message' : err[2]})]

def _json_ok(env, start_response, data):
    start_response('200 OK',[])
    return [json.dumps({'type': 'ok', 'data' : data})]


class ERROR_CODES:
    BAD_PARAMTER = (100, 'Bad paramter', '')
    FACEBOOK_NO_SESSION = (201, 'No valid Facebook session', '')
    FACEBOOK_NO_PERMISSION = (202, 'Not enough permission', 'You don\'t have enough permission for this request.')

class SimpleDBWRTY(SimpleDB):
    #This class adds the ability to retry put and get functions in the SimpleDB library.
    #it exposes all functions with the same interface.
    def __init__(self, aws_access_key, aws_secret_access_key, db='sdb.amazonaws.com',
                secure=True, encoder=AttributeEncoder(), retry_limit = 0):
        SimpleDB.__init__(self, aws_access_key, aws_secret_access_key, db, secure, encoder)
        self.retry_limit = retry_limit
    def get_attributes(self, domain, item, attributes=None):
        retry = 0
        while True:
            try:
                return SimpleDB.get_attributes(self, domain, item, attributes)
            except :
                if retry < self.retry_limit + 1:
                    retry = retry + 1
                else:
                    raise
    def put_attributes(self, domain, item, attributes):
        retry = 0
        while retry < self.retry_limit + 1:
            try:
                return SimpleDB.put_attributes(self, domain, item, attributes)
            except :
                if retry < self.retry_limit + 1:
                    retry = retry + 1
                else:
                    raise

def create_label(env, start_response, args):
    method = env['REQUEST_METHOD']
    #if method != 'POST':
    #    start_response('501 Not Implemented', [])
    #    return ['Unsupported']
    user = _validate_fb(env)
    print args
    if user:
        if ('gid' in args) and ('parent' in args) and ('name' in args) and ('nick' in args):
            try:
                gid = str(int(args['gid']))
            except:
                return _json_error(env, start_response, ERROR_CODES.BAD_PARAMTER)
            if not _can_access(gid, user):
                return _json_error(env, start_response, ERROR_CODES.FACEBOOK_NO_PERMISSION)
            if _is_group_admin(gid, user):
                shared = 'global'
            elif ('personal' not in args) or (str(args['personal']) != '1'):
                return _json_error(env, start_response, ERROR_CODES.FACEBOOK_NO_PERMISSION)
            if ('personal' in args) and (str(args['personal']) == '1'):
                gid = str(gid) + ':' + str(user['uid'])
                shared = 'personal'
                if ('shared' in args) and (str(args['shared']) == '1'):
                    shared = 'shared'
            sdb = SimpleDBWRTY(AWS_ACCESS_KEY, AWS_SECRET_ACCESS_KEY, retry_limit = RETRY_LIMIT)
            try:
                if not str(args['parent']) == '0':
                    parent = sdb.get_attributes(AWS_SDB_DOMAIN, gid, [args['parent']])
                    if not parent.has_key(args['parent']) or parent[args['parent']] is None:
                        return _json_error(env, start_response, ERROR_CODES.BAD_PARAMTER)
                label_id = hashlib.sha1(str(args['name']) + str(time.time())).hexdigest()
                sdb.put_attributes(AWS_SDB_DOMAIN, gid, [(label_id, shared, True), (label_id, base64.b64encode(args['name']), True), (label_id, base64.b64encode(args['nick']), True), (label_id, args['parent'], True)])
            except:
                raise
                start_response('503 Service Unavailable',[])
                return ['Temporarily not available']
            return _json_ok(env, start_response, label_id)
        return _json_error(env, start_response, ERROR_CODES.BAD_PARAMTER)
    return _json_error(env, start_response, ERROR_CODES.FACEBOOK_NO_SESSION)

def get_labels(env, start_response, args):
    method = env['REQUEST_METHOD']
    #if method != 'GET':
    #    start_response('501 Not Implemented', [])
    #    return ['Unsupported']
    user = _validate_fb(env)
    if user:
        if 'gid' not in args:
            return _json_error(env, start_response, ERROR_CODES.BAD_PARAMTER)
        try:
            gid = str(int(args['gid']))
        except:
            raise
            return _json_error(env, start_response, ERROR_CODES.BAD_PARAMTER)
        if _can_access(int(gid), user):
            shared = 'global'
            if 'uid' in args:
                try:
                    uid = str(int(args['uid']))
                    if uid != str(user['uid']):
                        shared = 'shared'
                    else:
                        shared = 'personal'
                except:
                    raise
                    return _json_error(env, start_response, ERROR_CODES.BAD_PARAMTER)
                gid = str(gid) + ':' + str(user['uid'])
            else:
                uid = str(user['uid'])
            try:
                sdb = SimpleDBWRTY(AWS_ACCESS_KEY, AWS_SECRET_ACCESS_KEY, retry_limit = RETRY_LIMIT)
                labels = sdb.get_attributes(AWS_SDB_DOMAIN, gid)
                easy_labels = {}
                for i in labels:
                    if ((shared == 'shared') and (labels[i][3] == 'shared')) or ((shared == 'personal') and (labels[i][3] in ['shared', 'personal'])) or (shared == 'global'):
                        easy_labels[i] = {'parent' : labels[i][0], 'name' : base64.b64decode(labels[i][1]), 'nick': base64.b64decode(labels[i][2]), 'shared' : labels[i][3]}
                return _json_ok(env, start_response, easy_labels)
            except:
                raise
                start_response('503 Service Unavailable',[])
                return ['Temporarily not available']
        else:
            return _json_error(env, start_response, ERROR_CODES.FACEBOOK_NO_PERMISSION)
    return _json_error(env, start_response, ERROR_CODES.FACEBOOK_NO_SESSION)
        
 
def request_handler(env, start_response):
    method = env['REQUEST_METHOD']
    path = env['PATH_INFO']
    if (method in ['GET', 'POST']):
        if path.strip('/') in allowed_functions:
            return globals()[path.strip('/')](env, start_response, _load_args(env))
        _load_pages()
        #return globals()[path.strip('/')](env, start_response)
        return load_group(path.strip('/'), env, start_response)
    logging.info('Invalid method and/or path from: %s'%(
        env['REMOTE_ADDR'],
        ))
    start_response('501 Not Implemented', [])
    return []

if __name__ == '__main__':
    print 'Serving on %s (%s)...' %(LISTEN_PORT, PROTOCOL)
    if PROTOCOL == 'http':
        WSGIServer((LISTEN_IP,LISTEN_PORT),request_handler).serve_forever()
    else:
        WSGIServer((LISTEN_IP,LISTEN_PORT), request_handler, keyfile='server.key', certfile='server.cert').serve_forever()

