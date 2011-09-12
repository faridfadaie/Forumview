from gevent.pywsgi import WSGIServer
import logging, sys

allowed_functions = ['']
page_names = ['load_group.html']
page_contents = {}
LISTEN_IP = '0.0.0.0'
LISTEN_PORT = 80
ACTIVATION_LIMIT = 3
AV_LIMIT = -1
CODEC_LIMIT = 3
RETRY_LIMIT = 3
PROTOCOL = 'http'

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

def request_handler(env, start_response):
    method = env['REQUEST_METHOD']
    path = env['PATH_INFO']
    if (method in ['GET', 'POST']):
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

