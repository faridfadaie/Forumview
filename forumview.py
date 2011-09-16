from gevent.pywsgi import WSGIServer
import facebook
from crm import load_enc_conf
from _gevent_helper import *
import gevent.pywsgi
import time, logging, sys, hashlib, base64
from simpledb import SimpleDB, SimpleDBError, AttributeEncoder
from retry import Retry

allowed_functions = ['get_post_labels', 'get_post_labels', 'get_posts', '/get_posts', '/assign_label', 'assign_label', '/create_label', 'create_label', '/get_labels', 'get_labels']
page_names = ['load_group.html']
page_contents = {}
LISTEN_IP = '0.0.0.0'
LISTEN_PORT = 20000
ACTIVATION_LIMIT = 3
AV_LIMIT = -1
CODEC_LIMIT = 3
RETRY_LIMIT = 3
PROTOCOL = 'http'
DYN_LOADING = True
config = load_enc_conf('init.cfg.enc')
FACEBOOK_KEY = config['FACEBOOK_KEY']
FACEBOOK_SECRET = config['FACEBOOK_SECRET'] 
AWS_ACCESS_KEY = config['AWS_ACCESS_KEY'] 
AWS_SECRET_ACCESS_KEY = config['AWS_SECRET_ACCESS_KEY'] 
AWS_SDB_LABELS_DOMAIN = 'test'
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
    obj = graph.get_object("%s" %gid)
    if obj.has_key('id'):
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

#class SimpleDBWRTY(SimpleDB):
    #This class adds the ability to retry put and get functions in the SimpleDB library.
    #it exposes all functions with the same interface.
#    def __init__(self, aws_access_key, aws_secret_access_key, db='sdb.amazonaws.com',
#                secure=True, encoder=AttributeEncoder(), retry_limit = 0):
#        SimpleDB.__init__(self, aws_access_key, aws_secret_access_key, db, secure, encoder)
#        self.retry_limit = retry_limit
#    def __getattribute__(self, name):
#        if name in ['select', 'get_attributes', 'put_attributes']:
#            retry = 0
#            while True:
#                try:
#                    return object.__getattribute__(self, name)
#                except:
#                    if retry < self.retry_limit + 1:
#                        retry = retry + 1
#                    else:
#                        raise
#        return object.__getattribute__(self, name)

def create_label(env, start_response, args):
    method = env['REQUEST_METHOD']
    #if method != 'POST':
    #    start_response('501 Not Implemented', [])
    #    return ['Unsupported']
    user = _validate_fb(env)
    print args
    if user:
        if ('gid' in args) and ('parent' in args) and ('name' in args) and ('nick' in args) and ('desc' in args):
            try:
                gid = str(int(args['gid']))
            except:
                return json_error(env, start_response, ERROR_CODES.BAD_PARAMTER, 'gid is not valid.')
            if not _can_access(gid, user):
                return json_error(env, start_response, ERROR_CODES.FACEBOOK_NO_PERMISSION, 'access to the object is denied.')
            layer_id = str(user['uid'])
            if _is_group_admin(gid, user):
                shared = 'global'
                layer_id = '0'
            elif ('personal' not in args) or (str(args['personal']) != '1'):
                return json_error(env, start_response, ERROR_CODES.BAR_PARAMTER, 'the personal view should be selected.')
            if ('personal' in args) and (str(args['personal']) == '1'):
                gid = str(gid) + ':' + str(user['uid'])
                shared = 'personal'
                if ('shared' in args) and (str(args['shared']) == '1'):
                    shared = 'shared'
            sdb = Retry(SimpleDB, RETRY_LIMIT, ['select', 'put_attributes', 'get_attributes'], AWS_ACCESS_KEY, AWS_SECRET_ACCESS_KEY)
            #sdb = SimpleDBWRTY(AWS_ACCESS_KEY, AWS_SECRET_ACCESS_KEY, retry_limit = RETRY_LIMIT)
            try:
                if not str(args['parent']) == '0':
                    parent = sdb.get_attributes(AWS_SDB_LABELS_DOMAIN, gid, [args['parent']])
                    if not parent.has_key(args['parent']) or parent[args['parent']] is None:
                        return json_error(env, start_response, ERROR_CODES.BAD_PARAMTER,'parent label_id is not passed.')
                label_id = hashlib.sha1(str(args['name']) + str(time.time())).hexdigest()
                sdb.put_attributes(AWS_SDB_LABELS_DOMAIN, gid, [(label_id, 'OBJ:' + gid.split(':')[0], True), 
                                                                (label_id, 'SHR:' + shared, True), (label_id, 'NAME:' + base64.b64encode(args['name']), True), 
                                                                (label_id, 'NIK:' + base64.b64encode(args['nick']), True), (label_id, 'PAR:' + args['parent'], True), 
                                                                (label_id, 'DESC:' + base64.b64encode(args['desc']), True), (label_id, 'CRT:' + layer_id, True)])
            except:
                raise
                start_response('503 Service Unavailable',[])
                return ['Temporarily not available']
            return json_ok(env, start_response, label_id)
        return json_error(env, start_response, ERROR_CODES.BAD_PARAMTER)
    return json_error(env, start_response, ERROR_CODES.FACEBOOK_NO_SESSION)

def _decode_label(lb):
    for j in lb:
        if j.find('SHR:') == 0:
            shared_status = j.strip('SHR:')
        if j.find('NAME:') == 0:
            name_status = j.strip('NAME:')
        if j.find('NIK:') == 0:
            nik_status = j.strip('NIK:')
        if j.find('PAR:') == 0:
            parent_status = j.strip('PAR:')
        if j.find('DESC:') == 0:
            desc_status = j.strip('DESC:')
        if j.find('CRT:') == 0:
            creator_status = j.strip('CRT:')
        if j.find('OBJ:') == 0:
            obj_status = j.strip('OBJ:')
    return shared_status, name_status, nik_status, parent_status, desc_status, creator_status, obj_status

def _decode_post(ps):
    for j in ps:
        if j.find('STICKY:') == 0:
            sticky = j.strip('STICKY:')
        if j.find('SHR:') == 0:
            shared_status = j.strip('SHR:')
    return sticky, shared_status


def get_labels(env, start_response, args):
    method = env['REQUEST_METHOD']
    #if method != 'GET':
    #    start_response('501 Not Implemented', [])
    #    return ['Unsupported']
    user = _validate_fb(env)
    if user:
        if 'gid' not in args:
            return json_error(env, start_response, ERROR_CODES.BAD_PARAMTER, 'gid is not passed.')
        try:
            gid = str(int(args['gid']))
        except:
            return json_error(env, start_response, ERROR_CODES.BAD_PARAMTER, 'gid is not valid.')
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
                    return json_error(env, start_response, ERROR_CODES.BAD_PARAMTER, 'uid is not valid.')
                gid = str(gid) + ':' + str(user['uid'])
            else:
                uid = str(user['uid'])
            try:
                sdb = Retry(SimpleDB, RETRY_LIMIT, ['select', 'put_attributes', 'get_attributes'], AWS_ACCESS_KEY, AWS_SECRET_ACCESS_KEY)
                #sdb = SimpleDBWRTY(AWS_ACCESS_KEY, AWS_SECRET_ACCESS_KEY, retry_limit = RETRY_LIMIT)
                labels = sdb.get_attributes(AWS_SDB_LABELS_DOMAIN, gid)
                easy_labels = {}
                for i in labels:
                    shared_status, name_status, nik_status, parent_status, desc_status, creator_status, obj_status = _decode_label(label[i])
                    if ((shared == 'shared') and (shared_status == 'shared'))\
                    or ((shared == 'personal') and (shared_status in ['shared', 'personal'])) \
                    or (shared == 'global'):
                        easy_labels[i] = {'obj_id' : obj_status, 'creator' : creator_status, 
                                          'parent' : parent_status, 'name' : base64.b64decode(name_status), 
                                          'nick': base64.b64decode(nik_status), 'shared' : shared_status, 'desc' : base64.b64decode(desc_status)}
                return json_ok(env, start_response, easy_labels)
            except:
                raise
                start_response('503 Service Unavailable',[])
                return ['Temporarily not available']
        else:
            return json_error(env, start_response, ERROR_CODES.NO_PERMISSION)
    return json_error(env, start_response, ERROR_CODES.FACEBOOK_NO_SESSION)
        
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

