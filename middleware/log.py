from pymemcache.client import base

client = base.Client(('localhost', 11211))

def on_visit(client):
    result = client.get('visitors')
    if result is None:
        result = 1
    else:
        result += 1
    client.set('visitors', result)