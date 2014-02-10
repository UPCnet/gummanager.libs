import json

def getConfig(item):
    config = json.loads(open('config.json').read())
    return config[item]