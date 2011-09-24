from gevent.pywsgi import WSGIServer
import facebook
#from crm import load_enc_conf
from _gevent_helper import *
import gevent.pywsgi
import time, logging, sys, hashlib, base64
from simpledb import SimpleDB, SimpleDBError, AttributeEncoder
from retry import Retry

allowed_functions = ['get_exceptions', '/get_exceptions', 'get_post_labels', 'get_post_labels', 'get_posts', '/get_posts', '/assign_label', 'assign_label', '/create_label', 'create_label', '/get_labels', 'get_labels']
page_names = ['load_group.html']
page_contents = {}
LISTEN_IP = '0.0.0.0'
LISTEN_PORT = 20000
RETRY_LIMIT = 3
PROTOCOL = 'http'
DYN_LOADING = True

SHARE_DEL = 'A:' 
NAME_DEL = 'B:'
NICK_DEL = 'C:'
PARENT_DEL = 'D:'
RULE_DEL = 'E:'

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
    if ('obj_id' in args) and ('parent' in args) and ('name' in args) and ('nick' in args) and ('rule' in args):
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
                                                            (label_id, RULE_DEL + args['rule'], True)])
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
    return shared_status, name, nick, parent, rule

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
    if 'obj_id' not in args:
        return json_error(env, start_response, ERROR_CODES.BAD_PARAMTER, 'obj_id is not passed.')
    try:
        obj_id = str(int(args['obj_id']))
    except:
        return json_error(env, start_response, ERROR_CODES.BAD_PARAMTER, 'obj_id is not valid.')
    admin = _is_admin(obj_id, user)
    if admin is None:
        return json_error(env, start_response, ERROR_CODES.FACEBOOK_NO_PERMISSION, 'access to the object is denied or the object is not supported.')
    if 'label_id' in args:
        sdb = Retry(SimpleDB, RETRY_LIMIT, ['select', 'put_attributes', 'get_attributes'], AWS_ACCESS_KEY, AWS_SECRET_ACCESS_KEY)
        try:
            exceptions = sdb.select(AWS_SDB_EXCEPTIONS_DOMAIN, 'select exclude, post_id from %s where label_id=`%s`' %(AWS_SDB_EXCEPTIONS_DOMAIN, args['label_id']) )
            return json_ok(env, start_response, exceptions)
        except:
            raise
            start_response('503 Service Unavailable',[])
            return ['Temporarily not available']
    if 'post_id' not in args:
        return json_error(env, start_response, ERROR_CODES.BAD_PARAMTER, 'post_id or label_id should be passed.')
    sdb = Retry(SimpleDB, RETRY_LIMIT, ['select', 'put_attributes', 'get_attributes'], AWS_ACCESS_KEY, AWS_SECRET_ACCESS_KEY)
    try:
        post_id = ''
        for i in args['post_id'].split(','):
            post_id = post_id + ',"%s`"' %i
        post_id = post_id.strip(',')
        exceptions = sdb.select(AWS_SDB_EXCEPTIONS_DOMAIN, 'select exclude, post_id, label_id from %s where post_id in (%s)' %(AWS_SDB_EXCEPTIONS_DOMAIN, post_id) )
        return json_ok(env, start_response, exceptions)
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
            shared_status, name, nick, parent, rule = _decode_label(labels[i])
            if ((shared == 'shared') and (shared_status == 'shared'))\
            or ((shared == 'personal') and (shared_status in ['shared', 'personal'])) \
            or (shared == 'global'):
                easy_labels[i] = {'parent' : parent, 'name' : name, 
                                  'nick': nick, 'shared' : shared_status, 'rule' : rule}
        return json_ok(env, start_response, easy_labels)
    except:
        raise
        start_response('503 Service Unavailable',[])
        return ['Temporarily not available']
        
def assign_label(env, start_response, args):
    method = env['REQUEST_METHOD']
    #if method != 'GET':
    #    start_response('501 Not Implemented', [])
    #    return ['Unsupported']
    user = _validate_fb(env)
    if user:
        if ('post_id' not in args) or ('label_id' not in args):
            return json_error(env, start_response, ERROR_CODES.BAD_PARAMTER)
        try:
            from_id, to_id, created_time, updated_time = _get_post_info(args['post_id'], user)
        except:
            return json_error(env, start_response, ERROR_CODES.BAD_PARAMTER, 'post_id is not valid or not accessible.')
        if from_id is None:
            return json_error(env, start_response, ERROR_CODES.BAD_PARAMTER, 'the post does not have a from_id field.')
        try:
            sdb = Retry(SimpleDB, RETRY_LIMIT, ['select', 'put_attributes', 'get_attributes'], AWS_ACCESS_KEY, AWS_SECRET_ACCESS_KEY)
            #sdb = SimpleDBWRTY(AWS_ACCESS_KEY, AWS_SECRET_ACCESS_KEY, retry_limit = RETRY_LIMIT)
            labels = sdb.select(AWS_SDB_LABELS_DOMAIN, "select `%s` from %s where `%s` is not null" %(args['label_id'], AWS_SDB_LABELS_DOMAIN, args['label_id']))
            if len(labels) == 0:    
                return json_error(env, start_response, ERROR_CODES.BAD_PARAMTER, 'the label_id is not a valid label or is not public.')
            shared_status, name_status, nik_status, parent_status, desc_status, creator_status, obj_id = _decode_label(labels[0].values()[0])
            if str(to_id) != obj_id:
                return json_error(env, start_response, ERROR_CODES.BAD_PARAMTER, 'the label is not defined for this object.')
            is_admin = _is_group_admin(to_id, user)
            if (shared_status == 'global') and (str(user['uid']) != str(from_id)) and (not is_admin):
                return json_error(env, start_response, ERROR_CODES.BAD_PARAMTER, 'only the admin or the author can assign global labels.')
            if (shared_status == 'shared') and (str(user['uid']) != str(from_id)) and (creator_status != str(user['uid'])):
                return json_error(env, start_response, ERROR_CODES.BAD_PARAMTER, 'only the label creator or the author can assign shared labels.')
            if ('sticky' in args) and (str(args['sticky']) == '1'):
                if (shared_status == 'global') and not is_admin:
                    return json_error(env, start_response, ERROR_CODES.NO_PERMISSION, 'only the admin can mark global labels as sticky.')
                if (shared_status in ['shared', 'personal']) and (creator_status != str(user['uid'])):
                    return json_error(env, start_response, ERROR_CODES.NO_PERMISSION, 'only the label creator can mark shared/personal labels as sticky.')
                sticky = '1'
            else:
                sticky = '0'
            if shared_status == 'global':
                itm = args['post_id']
                creator_status = '0'
            else:
                itm = args['post_id'] + ':' + creator_status
            sdb.put_attributes(AWS_SDB_POST_DOMAIN, itm, [('C_TIME', time.mktime(time.strptime(str(created_time), "%Y-%m-%dT%H:%M:%S+0000")), True),
                                                          ('U_TIME', time.mktime(time.strptime(str(updated_time), "%Y-%m-%dT%H:%M:%S+0000")), True),
                                                          (args['label_id'], 'STICKY:%s' %sticky, True), (args['label_id'], 'SHR:%s' %shared_status, True),
                                                          ('post_id', '%s' %args['post_id'].split(':')[0], True), ('layer_id', '%s' %creator_status, True)])
            return json_ok(env, start_response, {})
        except:
            raise
            start_response('503 Service Unavailable',[])
            return ['Temporarily not available']
    return json_error(env, start_response, ERROR_CODES.FACEBOOK_NO_SESSION)

def get_posts(env, start_response, args):
    method = env['REQUEST_METHOD']
    #if method != 'GET':
    #    start_response('501 Not Implemented', [])
    #    return ['Unsupported']
    user = _validate_fb(env)
    if user:
        if ('label_id' not in args) or ('up_to' not in args) or ('count' not in args):
            return json_error(env, start_response, ERROR_CODES.BAD_PARAMTER)
        try:
           up_to = int(args['up_to'])
           count = int(args['count'])
        except:
            return json_error(env, start_response, ERROR_CODES.BAD_PARAMTER, 'the up_to time stamp or the count value is not valid.')
        sdb = Retry(SimpleDB, RETRY_LIMIT, ['select', 'put_attributes', 'get_attributes'], AWS_ACCESS_KEY, AWS_SECRET_ACCESS_KEY)
        #sdb = SimpleDBWRTY(AWS_ACCESS_KEY, AWS_SECRET_ACCESS_KEY, retry_limit = RETRY_LIMIT)
        labels = sdb.select(AWS_SDB_LABELS_DOMAIN, "select `%s` from %s where `%s` is not null" %(args['label_id'], AWS_SDB_LABELS_DOMAIN, args['label_id']))
        if len(labels) == 0:
            return json_error(env, start_response, ERROR_CODES.BAD_PARAMTER, 'the label_id is not a valid label or is not public.')
        shared_status, name_status, nik_status, parent_status, desc_status, creator_status, obj_id = _decode_label(labels[0].values()[0])
        if shared_status in ['global', 'shared'] and (not _can_access(obj_id, user)):
            return json_error(env, start_response, ERROR_CODES.NO_PERMISSION, 'access to the requested object is denied.')
        if (shared_status == 'personal') and (str(user['uid']) != creator_status):
            return json_error(env, start_response, ERROR_CODES.NO_PERMISSION, 'this is a personal label and is not shared. access is denied.')
        if shared_status != 'global':
            gid = obj_id + ':' + str(user['uid']) 
        else:
            gid = obj_id
        try:
            posts = sdb.select(AWS_SDB_POST_DOMAIN, 'select * from %s where U_TIME<"%s" or `%s`="STICKY:1" limit %s' %(AWS_SDB_POST_DOMAIN, up_to, args['label_id'], count))
        except:
            raise
            start_response('503 Service Unavailable',[])
            return ['Temporarily not available']
        post_list = []
        for i in posts:
            sticky, shared_status = _decode_post(i[args['label_id']])
            post_list.append({'created' : i['C_TIME'], 'updated': i['U_TIME'], 'post_id' : i['post_id'], 'shared' : shared_status, 'sticky' : sticky, 'layer_id' : i['layer_id']})
        return json_ok(env, start_response, post_list)
    return json_error(env, start_response, ERROR_CODES.FACEBOOK_NO_SESSION)
    

def get_post_labels(env, start_response, args):
    method = env['REQUEST_METHOD']
    #if method != 'GET':
    #    start_response('501 Not Implemented', [])
    #    return ['Unsupported']
    user = _validate_fb(env)
    if user is None:
        return json_error(env, start_response, ERROR_CODES.FACEBOOK_NO_SESSION)
    if ('layer_id' not in args) or ('gid' not in args) or ('post_list' not in args):
        return json_error(env, start_response, ERROR_CODES.BAD_PARAMTER)
    post_list = ''
    for i in args['post_list'].split(','):
        post_list = post_list + ",'" + i + "'"
    post_list = post_list.strip(',')
    try:
        gid = int(args['gid'])
    except:
        return json_error(env, start_response, ERROR_CODES.BAD_PARAMTER, 'gid is not valid.')
    if not _can_access(args['gid'], user):
        return json_error(env, start_response, ERROR_CODES.FACEBOOK_NO_PERMISSION)
    #sdb = SimpleDBWRTY(AWS_ACCESS_KEY, AWS_SECRET_ACCESS_KEY, retry_limit = RETRY_LIMIT)
    sdb = Retry(SimpleDB, RETRY_LIMIT, ['select'], AWS_ACCESS_KEY, AWS_SECRET_ACCESS_KEY)
    if args['layer_id'] == 'global':
        shared = ['SHR:global']
        layer_id = '0'
    else:
        if str(args['layer_id']) == str(user['uid']):
            shared = ['SHR:personal', 'SHR:shared']
        else:
            shared = ['SHR:shared']
        layer_id = str(args['layer_id'])
    labels = sdb.select(AWS_SDB_POST_DOMAIN, "select * from %s where post_id in (%s) and layer_id='%s'" %(AWS_SDB_POST_DOMAIN, post_list, layer_id)) 
    mapping = {}
    for i in labels:
        label_list = []
        for j in i:
            if type(i[j])==list:
                if ((len(shared) == 1) and (shared[0] in i[j])) or ((len(shared) == 2) and (shared[0] in i[j]) or (shared[1] in i[j])):
                    label_list.append(j)
        mapping[i['post_id']] = label_list
    return json_ok(env, start_response, mapping)
        
def request_handler(env, start_response):
    method = env['REQUEST_METHOD']
    path = env['PATH_INFO']
    if (method in ['GET', 'POST']):
        if path.strip('/') in allowed_functions:
            return globals()[path.strip('/')](env, start_response, load_args(env))
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

