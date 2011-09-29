from gevent.pywsgi import WSGIServer
import facebook
#from crm import load_enc_conf
from _gevent_helper import *
import gevent.pywsgi
import time, logging, sys, hashlib, base64
from simpledb import SimpleDB, SimpleDBError, AttributeEncoder
from retry import Retry

allowed_functions = ['script', 'css','set_exception', 'get_exceptions', 'get_post_labels', 'get_post_labels', 'get_posts', 'assign_label', 'create_label', 'get_labels']
page_names = ['load_group.html']
page_contents = {}
LISTEN_IP = '0.0.0.0'
LISTEN_PORT = 10000
RETRY_LIMIT = 3
PROTOCOL = 'http'
DYN_LOADING = True

SHARE_DEL = 'A:' 
NAME_DEL = 'B:'
NICK_DEL = 'C:'
PARENT_DEL = 'D:'
RULE_DEL = 'E:'
COL_DEL = 'F:'

config = {'FACEBOOK_SECRET': 'bba342dc751c88d7522ce822d4d30ab8', 'AWS_ACCESS_KEY': 'AKIAJ36DOHUEJB4QN5WA', 'FACEBOOK_KEY': '246575252046549', 'AWS_SECRET_ACCESS_KEY': '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'}
#load_enc_conf('init.cfg.enc')
FACEBOOK_KEY = config['FACEBOOK_KEY']
FACEBOOK_SECRET = config['FACEBOOK_SECRET'] 
AWS_ACCESS_KEY = config['AWS_ACCESS_KEY'] 
AWS_SECRET_ACCESS_KEY = config['AWS_SECRET_ACCESS_KEY'] 
AWS_SDB_LABELS_DOMAIN = 'labels'
AWS_SDB_EXCEPTIONS_DOMAIN = 'exceptions'
AWS_SDB_POST_DOMAIN = 'test2'
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
    return user

def _detect_obj_type(obj_id, user):
    graph = facebook.GraphAPI(user["access_token"])
    obj = graph.get_object("%s" %obj_id)
    if not obj.has_key('id'):
        return None, None
    if obj.has_key('owner'):
        return 'group', obj['id']
    if obj.has_key('start_time'):
        return 'event', obj['id']
    if obj.has_key('first_name'):
        return 'profile', obj['id']
    if obj.has_key('likes'):
        return 'page', obj['id']
    if obj.has_key('canvas_name'):
        return 'app', obj['id']
    return 'unsupported', obj['id']

def _is_admin(obj_id, user):
    obj_type, id = _detect_obj_type(obj_id, user)
    if (obj_type is None) or obj_type in ['unsupported', 'canvas_name', 'event']:
        return None
    if obj_type == 'profile':
        if user['uid'] == id:
            return True
        return False
    if obj_type == 'group':
        graph = facebook.GraphAPI(user["access_token"])
        groups = graph.get_connections("me", "groups")
        for i in groups['data']:
            if (i['id'] == id) and (i.has_key('administrator')):
                return True
        return False
    if obj_type == 'page':
        graph = facebook.GraphAPI(user["access_token"])
        accounts = graph.get_connections("me", "accounts")
        for i in accounts['data']:
            if i['id'] == id:
                return True
        return False

def _get_post_info(post_id, user):
    graph = facebook.GraphAPI(user["access_token"])
    obj = graph.get_object("%s" %post_id)
    from_id = None
    to_id = None
    created_time = None
    updated_time = None
    if obj.has_key('from'):
        from_id = obj['from']['id']
    if obj.has_key('to') and obj['to'].has_key('data') and len(obj['to']['data']) > 0:
        to_id = obj['to']['data'][0]['id']
    if obj.has_key('created_time'):
        created_time = obj['created_time']
    if obj.has_key('updated_time'):
        updated_time = obj['updated_time']
    return from_id, to_id, created_time, updated_time

def create_label(env, start_response, args):
    method = env['REQUEST_METHOD']
    #if method != 'POST':
    #    start_response('501 Not Implemented', [])
    #    return ['Unsupported']
    user = _validate_fb(env)
    if user is None:
        return json_error(env, start_response, ERROR_CODES.FACEBOOK_NO_SESSION)
    if ('obj_id' in args) and ('parent' in args) and ('name' in args) and ('nick' in args) and ('rule' in args) and ('color' in args):
        try:
            obj_id = str(int(args['obj_id']))
        except:
            return json_error(env, start_response, ERROR_CODES.BAD_PARAMTER, 'obj_id is not valid.')
        layer_id = str(user['uid'])
        admin = _is_admin(obj_id, user)
        if admin is None:
            return json_error(env, start_response, ERROR_CODES.FACEBOOK_NO_PERMISSION, 'access to the object is denied or the object is not supported.')
        if admin:
            shared = 'global'
            layer_id = '0'
        elif ('personal' not in args) or (str(args['personal']) != '1'):
            return json_error(env, start_response, ERROR_CODES.BAD_PARAMTER, 'the personal view should be selected.')
        if ('personal' in args) and (str(args['personal']) == '1'):
            obj_id = str(obj_id) + ':' + str(user['uid'])
            shared = 'personal'
            if ('shared' in args) and (str(args['shared']) == '1'):
                shared = 'shared'
        sdb = Retry(SimpleDB, RETRY_LIMIT, ['select', 'put_attributes', 'get_attributes'], AWS_ACCESS_KEY, AWS_SECRET_ACCESS_KEY)
        #sdb = SimpleDBWRTY(AWS_ACCESS_KEY, AWS_SECRET_ACCESS_KEY, retry_limit = RETRY_LIMIT)
        try:
            if not str(args['parent']) == '0':
                parent = sdb.get_attributes(AWS_SDB_LABELS_DOMAIN, obj_id, [args['parent']])
                if not parent.has_key(args['parent']) or parent[args['parent']] is None:
                    return json_error(env, start_response, ERROR_CODES.BAD_PARAMTER,'parent label_id is not passed.')
            label_id = hashlib.sha1(str(args['name']) + str(time.time())).hexdigest()
            sdb.put_attributes(AWS_SDB_LABELS_DOMAIN, obj_id, [(label_id, SHARE_DEL + shared, True), 
                                                            (label_id, NAME_DEL + args['name'], True), 
                                                            (label_id, NICK_DEL + args['nick'], True), 
                                                            (label_id, PARENT_DEL + args['parent'], True), 
                                                            (label_id, RULE_DEL + args['rule'], True),
                                                            ('owned', user['uid'], True),
                                                            ('obj_id', obj_id.split(':')[0], True),
                                                            (label_id, COL_DEL + args['color'], True)])
        except:
            raise
            start_response('503 Service Unavailable',[])
            return ['Temporarily not available']
        return json_ok(env, start_response, label_id)
    return json_error(env, start_response, ERROR_CODES.BAD_PARAMTER)

def _decode_label(lb):
    for j in lb:
        if j.find(SHARE_DEL) == 0:
            shared_status = j.strip(SHARE_DEL)
        if j.find(NAME_DEL) == 0:
            name = j.strip(NAME_DEL)
        if j.find(NICK_DEL) == 0:
            nick = j.strip(NICK_DEL)
        if j.find(PARENT_DEL) == 0:
            parent = j.strip(PARENT_DEL)
        if j.find(RULE_DEL) == 0:
            rule = j.strip(RULE_DEL)
        if j.find(COL_DEL) == 0:
            color = j.strip(COL_DEL)

    return shared_status, name, nick, parent, rule, color

def _decode_post(ps):
    for j in ps:
        if j.find('STICKY:') == 0:
            sticky = j.strip('STICKY:')
        if j.find('SHR:') == 0:
            shared_status = j.strip('SHR:')
    return sticky, shared_status

def get_exceptions(env, start_response, args):
    method = env['REQUEST_METHOD']
    #if method != 'GET':
    #    start_response('501 Not Implemented', [])
    #    return ['Unsupported']
    user = _validate_fb(env)
    if user is None:
        return json_error(env, start_response, ERROR_CODES.FACEBOOK_NO_SESSION)
    if 'label_id' in args:
        sdb = Retry(SimpleDB, RETRY_LIMIT, ['select', 'put_attributes', 'get_attributes'], AWS_ACCESS_KEY, AWS_SECRET_ACCESS_KEY)
        try:
            print 'select excluded, post_id from %s where label_id="%s"' %(AWS_SDB_EXCEPTIONS_DOMAIN, args['label_id'])
            exceptions = sdb.select(AWS_SDB_EXCEPTIONS_DOMAIN, 'select excluded, post_id from %s where label_id="%s"' %(AWS_SDB_EXCEPTIONS_DOMAIN, args['label_id']) )
            post_list = {}
            for i in exceptions:
                post_list[i['post_id']] = i['excluded']
            return json_ok(env, start_response, post_list)
        except:
            raise
            start_response('503 Service Unavailable',[])
            return ['Temporarily not available']
    if 'post_id' not in args:
        return json_error(env, start_response, ERROR_CODES.BAD_PARAMTER, 'post_id or label_id should be passed.')
    sdb = Retry(SimpleDB, RETRY_LIMIT, ['select', 'put_attributes', 'get_attributes'], AWS_ACCESS_KEY, AWS_SECRET_ACCESS_KEY)
    try:
        post_list = {}
        post_id = ''
        for i in args['post_id'].split(','):
            post_id = post_id + ',"%s"' %i
        post_id = post_id.strip(',')
        exceptions = sdb.select(AWS_SDB_EXCEPTIONS_DOMAIN, 'select excluded, post_id, label_id from %s where post_id in (%s)' %(AWS_SDB_EXCEPTIONS_DOMAIN, post_id) )
        for i in exceptions:
            post_list[i['post_id']] = {'excluded' : i['excluded'], 'label_id' : i['label_id']}
        return json_ok(env, start_response, post_list)
    except:
        raise
        start_response('503 Service Unavailable',[])
        return ['Temporarily not available']

def get_labels(env, start_response, args):
    method = env['REQUEST_METHOD']
    #if method != 'GET':
    #    start_response('501 Not Implemented', [])
    #    return ['Unsupported']
    user = _validate_fb(env)
    if user is None:
        return json_error(env, start_response, ERROR_CODES.FACEBOOK_NO_SESSION)
    if 'obj_id' not in args:
        return json_error(env, start_response, ERROR_CODES.BAD_PARAMTER, 'obj_id is not passed.')
    try:
        obj_id = str(int(args['obj_id']))
    except:
        return json_error(env, start_response, ERROR_CODES.BAD_PARAMTER, 'obj_id is not valid.')
    admin = _is_admin(obj_id, user)
    if admin is None:
        return json_error(env, start_response, ERROR_CODES.FACEBOOK_NO_PERMISSION, 'access to the object is denied or the object is not supported.')
    shared = 'global'
    if 'uid' in args:
        try:
            uid = str(int(args['uid']))
            if uid != str(user['uid']):
                shared = 'shared'
            else:
                shared = 'personal'
        except:
            return json_error(env, start_response, ERROR_CODES.BAD_PARAMTER, 'uid is not valid.')
        obj_id = obj_id + ':' + str(user['uid'])
    else:
        uid = str(user['uid'])
    try:
        sdb = Retry(SimpleDB, RETRY_LIMIT, ['select', 'put_attributes', 'get_attributes'], AWS_ACCESS_KEY, AWS_SECRET_ACCESS_KEY)
        labels = sdb.get_attributes(AWS_SDB_LABELS_DOMAIN, obj_id)
        easy_labels = {}
        for i in labels:
            shared_status, name, nick, parent, rule, color = _decode_label(labels[i])
            if ((shared == 'shared') and (shared_status == 'shared'))\
            or ((shared == 'personal') and (shared_status in ['shared', 'personal'])) \
            or (shared == 'global'):
                easy_labels[i] = {'parent' : parent, 'name' : name, 
                                  'nick': nick, 'shared' : shared_status, 'rule' : rule, 'color' : color}
        return json_ok(env, start_response, easy_labels)
    except:
        raise
        start_response('503 Service Unavailable',[])
        return ['Temporarily not available']
        
def set_exception(env, start_response, args):
    method = env['REQUEST_METHOD']
    #if method != 'GET':
    #    start_response('501 Not Implemented', [])
    #    return ['Unsupported']
    user = _validate_fb(env)
    if user is None:
        return json_error(env, start_response, ERROR_CODES.FACEBOOK_NO_SESSION)
    if ('post_id' not in args) or ('label_id' not in args) or ('excluded' not in args):
        return json_error(env, start_response, ERROR_CODES.BAD_PARAMTER)
    try:
        from_id, to_id, created_time, updated_time = _get_post_info(args['post_id'], user)
    except:
        return json_error(env, start_response, ERROR_CODES.BAD_PARAMTER, 'post_id is not valid or not accessible.')
    if from_id is None:
        return json_error(env, start_response, ERROR_CODES.BAD_PARAMTER, 'the post does not have a from_id field.')
    try:
        sdb = Retry(SimpleDB, RETRY_LIMIT, ['select', 'put_attributes', 'get_attributes'], AWS_ACCESS_KEY, AWS_SECRET_ACCESS_KEY)
        labels = sdb.select(AWS_SDB_LABELS_DOMAIN, "select `%s` from %s where `%s` is not null" %(args['label_id'], AWS_SDB_LABELS_DOMAIN, args['label_id']))
        if len(labels) == 0:    
            return json_error(env, start_response, ERROR_CODES.BAD_PARAMTER, 'the label_id is not a valid label or is not public.')
        if labels[0].name.count(':') == 0:
            owner = 'admin'
        else:
            owner = labels[0].name.split(':')[1]
        obj_id = labels[0].name.split(':')[0]
        shared_status, name, nick, parent, rule, color = _decode_label(labels[0].values()[0])
        if str(to_id) != obj_id:
            return json_error(env, start_response, ERROR_CODES.BAD_PARAMTER, 'the label is not defined for this object.')
        is_admin = _is_admin(to_id, user)
        if (shared_status == 'global') and (str(user['uid']) != str(from_id)) and (not is_admin):
            return json_error(env, start_response, ERROR_CODES.BAD_PARAMTER, 'only the admin or the author can assign global labels.')
        if (shared_status == 'shared') and (str(user['uid']) != str(from_id)) and (creator_status != str(user['uid'])):
            return json_error(env, start_response, ERROR_CODES.BAD_PARAMTER, 'only the label creator or the author can assign shared labels.')
        itm = args['label_id'] + ':' + args['post_id']
        if args['excluded'] == '1':
            excluded = '1'
        else:
            excluded = '0'
        sdb.put_attributes(AWS_SDB_EXCEPTIONS_DOMAIN, itm, [('excluded', excluded, True),
                                                      ('label_id', args['label_id'], True),
                                                      ('post_id', args['post_id'], True),
                                                      ('creator', str(user['uid']), True)])
        return json_ok(env, start_response, {})
    except:
        raise
        start_response('503 Service Unavailable',[])
        return ['Temporarily not available']

def css(env, start_response, args):
    if (len(args['list']) !=1) or (not args['list'][0].isalnum):
        return json_error(env, start_response, ERROR_CODES.BAD_PARAMTER, 'not a valid css file request.')
    f = open('css/%s.css' %args['list'][0], 'r')
    try:
        start_response('200 OK', [])
        ret = f.read()
        f.close()
    except:
        start_response('503 Service Unavailable',[])
        return []
    return [ret]

def script(env, start_response, args):
    if (len(args['list']) !=1) or (not args['list'][0].isalnum):
        return json_error(env, start_response, ERROR_CODES.BAD_PARAMTER, 'not a valid script request.')
    f = open('scripts/%s.js' %args['list'][0], 'r')
    try:
        start_response('200 OK', [])
        ret = f.read()
        f.close()
    except:
        start_response('503 Service Unavailable',[])
        return []
    return [ret]



def request_handler(env, start_response):
    method = env['REQUEST_METHOD']
    path = env['PATH_INFO']
    if (method in ['GET', 'POST']):
        if (path.count('/') > 1) and path.split('/')[1] in allowed_functions:
        #if path.strip('/') in allowed_functions:
            params = load_args(env)
            params['list'] = path.split('/')[2:]
            return globals()[path.split('/')[1]](env, start_response, params)
        if DYN_LOADING:
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

