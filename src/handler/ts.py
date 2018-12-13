# coding=utf-8

import IndexmHandler
#from manager import client

#my_client = None

#payload = '{"commands":[{"command":"zcl on-off on"},{"command":"plugin device-table send {D0CF5EFFFEF4E41F} 0x1"}]}'
payload = '{"commands":[{"command":"zcl on-off %s"},{"command":"plugin device-table send {%s} 0x%s"}]}' % ('on', 'D0CF5EFFFEF4E41F', '1')
if __name__ == '__main__':
    print '___ts____ts___'
    IndexmHandler.my_client.publish('gw/%s/commands', payload, qos=0, retain=False)







