import urllib2
import json

def load_args(env):
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

def json_error(env, start_response, err, msg = None):
    start_response('200 OK',[])
    if msg is None:
        msg = err[2]
    return [json.dumps({'type': 'error', 'code' : err[0], 'reason' : err[1], 'message' : msg})]

def json_ok(env, start_response, data):
    start_response('200 OK',[])
    return [json.dumps({'type': 'ok', 'data' : data})]

class ERROR_CODES:
    BAD_PARAMTER = (100, 'Bad paramter', '')
    NO_PERMISSION = (101, 'Not enough permission', 'You don\'t have enough permission for this request.')
    FACEBOOK_NO_SESSION = (201, 'No valid Facebook session', '')
    FACEBOOK_NO_PERMISSION = (202, 'Not enough Facebook permission', 'You don\'t have enough permission for this request.')


