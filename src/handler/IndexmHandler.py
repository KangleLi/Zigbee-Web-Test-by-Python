#!/usr/bin/env python
#coding=utf8


from lib.route import route
from tornado.websocket import WebSocketHandler
from tornado.web import RequestHandler
import json
import socket


socket_handlers = set()
JOIN_TOPIC = '/network/join'
COMMAND_TOPIC = '/device/command'

# JOIN_TOPIC_SI = 'gw/90FD9FFFFE19BB86/commands'
JOIN_TOPIC_SI = 'gw/%s/commands'

# COMMAND_SI = 'gw/90FD9FFFFE19BB86/commands'
COMMAND_SI = 'gw/%s/commands'
IS_WRITE = False


def send_message(message):
    for handler in socket_handlers:
        try:
            handler.write_message(message)
        except:
            print 'websocket msg send error'


@route(r'/', name='indexm') #首页
# class IndexmHandler(AdminBaseHandler):
class IndexmHandler(RequestHandler):

    def get(self):
        macMap = self.application.macMap
        ip = macMap['ip']
        # s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # s.connect(('8.8.8.8', 80))
        # ip = s.getsockname()[0]
        self.render('t_index.html', ip=ip)
        # self.render('test.html')


@route(r'/startWS', name='startWS')
class WSHandler(WebSocketHandler):

    def open(self):
        print 'open ws.....'
        global socket_handlers
        socket_handlers.add(self)
        # self.application.mqttClient.publish("test", "ppp MQTT", qos=0, retain=False)
        self.write_message("send ws msg")

    def on_message(self, message):
        print 'recive ws msg ....'
        macMap = self.application.macMap
        print "cache:macMap:%s" % macMap
        for k, v in macMap.items():
            msg = {}
            print "add new device to front end from cache####"
            if k != 'ip':
                msg['Action'] = 'ReportJoin'
                if not v.has_key('deviceType'):
                    print 'new device, not input type'
                    continue
                if v['deviceType'] == 'unknow':
                    print 'not found'
                    continue
                msg['DeviceType'] = v['deviceType']
                print "cache:devcie:%s" % v
                msg['Address'] = k
                msgStr = json.dumps(msg)

                self.write_message(msgStr)
            else:
                print 'ip:%s' % k

    def on_close(self):
        print 'close ws....'

    def check_origin(self, origin):
        return True


@route(r'/join', name='join')
class JoinNetworkHandler(RequestHandler):

    def get(self):
        print "join pub msg"
        global JOIN_TOPIC_SI
        global COMMAND_SI
        print self.application.gwID['id']
        global IS_WRITE
        if not IS_WRITE:
            JOIN_TOPIC_SI = JOIN_TOPIC_SI % self.application.gwID['id']
            COMMAND_SI = COMMAND_SI % self.application.gwID['id']
            IS_WRITE = True
        joinMsg = '{"commands":[{"command":"plugin network-creator-security open-network","postDelayMs":100}]}'
        self.application.mqttClient.publish(JOIN_TOPIC_SI, joinMsg, qos=0, retain=False)


@route(r'/leave', name='leave')
class LeaveNetworkHandler(RequestHandler):

    def get(self):
        print "start leave"
        address = self.get_argument("address", None)
        macMap = self.application.macMap
        # address = '0x%s' % address
        print "leave:address:%s" % address
        if macMap.has_key(address):
            nodeId = macMap[address]['nodeId']
            leaveMsg = '{"commands":[{"commandcli":"zdo leave %s 0 0"}]}' % nodeId
            self.application.mqttClient.publish(COMMAND_SI, leaveMsg, qos=0, retain=False)
            print macMap
            macMap.pop(address, False)
            print macMap
        else:
            print "not found address:%s" % address



@route(r'/getDevices', name='getDevices')
class DevicesHandler(RequestHandler):
    def get(self):
        print "getDevices"
        # {"Address": "000D6F0011002B5F", "GroupId": "0",
        #  "EndpointId": "1", "CommandType": "0106",
        #  "Command": {"Type": "1101", "State": "1"}}
        address = self.get_argument("address", None)
        macMap = self.application.macMap
        # macMap = {'0x1111111':{'keys':['1','2','3'], 'isScen':False}}
        # address = '0x%s' % address
        keys = self.getDeviceKeysById(address)
        # print "DevicesHandler:address:%s" % address
        device = []
        for item in macMap.keys():
            if item == 'ip':
                continue
            isScen = macMap[item]['isScen']
            if not isScen:
                device = device + self.getDeviceKeysById(item)
        # keys = macMap[address]['keys']
        # keys = ['1', '2', '3']
        # for i in range(0, len(keys)):
        #     keys[i] = address + keys[i]
        # print "keys:%s" % keys
        ret = {}
        ret['keys'] = keys
        ret['devices'] = device
        msgStr = json.dumps(ret)
        self.write(ret)
        # cmd = self.get_argument("cmd", None)
        # cmdParse = cmd.split("@")
    def getDeviceKeysById(self, address):
        macMap = self.application.macMap
        # macMap = {'0x1111111': {'keys': ['1', '2', '3']}}
        print "DevicesHandler:address:%s" % address
        keys = [] if not macMap.has_key(address) else macMap[address]['keys']
        # keys = ['1', '2', '3']
        keyList = []
        for i in range(0, len(keys)):
            kStr = address + '@' + keys[i]
            keyList.append(kStr)
        print "keys:%s" % keys
        return keyList


@route(r'/bind', name='bind')
class BindHandler(RequestHandler):
    def get(self):
        print "bind"
        macMap = self.application.macMap
        # {"Address": "000D6F0011002B5F", "GroupId": "0",
        #  "EndpointId": "1", "CommandType": "0106",
        #  "Command": {"Type": "1101", "State": "1"}}
        key = self.get_argument("key", None)
        device = self.get_argument("device", None)

        keyArray = key.split("@")
        scenAddress = keyArray[0][2:]
        scenKey = keyArray[1]
        sIndex = '0x%s' % scenAddress
        sNodeId = macMap[sIndex]['nodeId']

        deviceArray = device.split("@")
        devAddress = deviceArray[0][2:]
        devKey = deviceArray[1]
        devIndex = '0x%s' % devAddress
        devNodeId = macMap[devIndex]['nodeId']
        # ret = {}
        # [dest 节点iD]  [远程设备源ep]  [远程ep]  [cluster]  [远程EUI]  [bind的dest EUI]
        stoDevStr = '{"commands":[{"commandcli":"zdo bind %s %s %s 0x0006 {%s} {%s}"}]}'\
                    % (sNodeId, scenKey, devKey, scenAddress, devAddress)
        print "bind:stodev:%s" % stoDevStr
        self.application.mqttClient.publish(COMMAND_SI, stoDevStr, qos=0, retain=False)
        devToSStr = '{"commands":[{"commandcli":"zdo bind %s %s %s 0x0006 {%s} {%s}"}]}' \
                    % (devNodeId, devKey, scenKey, devAddress, scenAddress)
        print "bind:devtos:%s" % devToSStr
        self.application.mqttClient.publish(COMMAND_SI, devToSStr, qos=0, retain=False)
        # zdo bind 0x151D 1 1 0x0006 {D0CF5EFFFEF4E41F} {D0CF5EFFFEF7315A}
        # ret['keys'] = [1111, 2222, 3333]
        # ret['devices'] = ['a1', 'a2', 'b1']
        # msgStr = json.dumps(ret)
        # self.write(ret)
        led = macMap[sIndex]['lightStatus']
        if led:
            state = '0'
        else:
            state = '1'
        nodeId = sNodeId
        print "bind:led:nodeId:%s" % nodeId
        model1 = '{"commands": [{"commandcli": "zcl mfg-code 0x1254 "}]}'
        print "bind:led:model1:%s" % model1
        self.application.mqttClient.publish(COMMAND_SI, model1, qos=0, retain=False)
        model2 = '{"commands": [{"commandcli": "zcl global write 0xFC56 0x0000 0x20 {0%s}"}]}' % state
        print "bind:led:model2:%s" % model2
        self.application.mqttClient.publish(COMMAND_SI, model2, qos=0, retain=False)
        model3 = '{"commands": [{"commandcli": "send %s 1 1"}]}' % nodeId
        print "bind:led:model3:%s" % model3
        self.application.mqttClient.publish(COMMAND_SI, model3, qos=0, retain=False)


@route(r'/unbind', name='unbind')
class UnBindHandler(RequestHandler):
    def get(self):
        print "unbind"
        macMap = self.application.macMap
        key = self.get_argument("key", None)
        device = self.get_argument("device", None)

        keyArray = key.split("@")
        scenAddress = keyArray[0][2:]
        scenKey = keyArray[1]
        sIndex = '0x%s' % scenAddress
        sNodeId = macMap[sIndex]['nodeId']

        deviceArray = device.split("@")
        devAddress = deviceArray[0][2:]
        devKey = deviceArray[1]
        devIndex = '0x%s' % devAddress
        devNodeId = macMap[devIndex]['nodeId']
        # ret = {}
        #zdo unbind unicast sNodeId {scenAddress} scenKey 0x0006 {devAddress} devKey
        stoDevUnStr = '{"commands":[{"commandcli":"zdo unbind unicast %s {%s} %s 0x0006 {%s} %s"}]}'\
                    % (sNodeId, scenAddress, scenKey, devAddress, devKey)
        print "unbind:stodev:%s" % stoDevUnStr
        self.application.mqttClient.publish(COMMAND_SI, stoDevUnStr, qos=0, retain=False)
        devToSUnStr = '{"commands":[{"commandcli":"zdo unbind unicast %s {%s} %s 0x0006 {%s} %s"}]}' \
                    % (devNodeId, devAddress, devKey, scenAddress, scenKey)
        print "unbind:devtos:%s" % devToSUnStr
        self.application.mqttClient.publish(COMMAND_SI, devToSUnStr, qos=0, retain=False)


@route(r'/getDevMethod', name='getDevMethod')
class GetDevMethod(RequestHandler):
    def get(self):
        print "get device method"
        macMap = self.application.macMap
        key = self.get_argument("address", None)

        keyArray = key.split("@")
        # keyArray:[u'0x90FD9FFFFEAB6AEA', u'1']

        device_type = self.application.macMap[keyArray[0]]['deviceType']
        # 判断是否为窗帘
        if device_type[0:3] == '300':
            op = ['c0%', 'c10%', 'c20%', 'c30%', 'c40%', 'c50%', 'c60%', 'c70%', 'c80%', 'c90%', 'c100%']
        else:
            op = ['on', 'off']
        opStr = json.dumps(op)

        self.write(opStr)

        # ret = {}
        #zdo unbind unicast sNodeId {scenAddress} scenKey 0x0006 {devAddress} devKey
        # stoDevUnStr = '{"commands":[{"commandcli":"zdo unbind unicast %s {%s} %s 0x0006 {%s} %s"}]}'\
        #             % (sNodeId, scenAddress, scenKey, devAddress, devKey)


@route(r'/createScen', name='createScen')
class CreateScen(RequestHandler):
    def get(self):
        macMap = self.application.macMap
        scen = self.get_argument("scen", None)
        scen = json.loads(scen)
        print "CreateScen method********************************************************&*&*&*&*****,%s" % scen
        model1 = '{"commands": [{"commandcli": "zcl groups add 0x01 \\"1\\""}]}'
        # self.application.mqttClient.publish(COMMAND_TOPIC, model1, qos=0, retain=False)
        model2 = '{"commands": [{"commandcli": "send %s 1 %s"}]}'
        model3 = '{"commands": [{"commandcli": "zcl scenes add 0x0001 %s 0X0000 \\"%s\\" %s"}]}'
        scenID = None
        scenName = None
        length = len(scen)

        for i in range(0, length):
            scenStr = scen[i]
            cmd = scenStr.split(':')
            opKey = cmd[2]
            # 灯
            if opKey == 'on':
                extensionField = '0x01010006'
            elif opKey == 'off':
                extensionField = '0x00010006'
            # 窗帘
            elif opKey == 'c0%':
                extensionField = '0x01010008'
            elif opKey == 'c10%':
                extensionField = '0x19010008'
            elif opKey == 'c20%':
                extensionField = '0x33010008'
            elif opKey == 'c30%':
                extensionField = '0x4C010008'
            elif opKey == 'c40%':
                extensionField = '0x66010008'
            elif opKey == 'c50%':
                extensionField = '0x7F010008'
            elif opKey == 'c60%':
                extensionField = '0x99010008'
            elif opKey == 'c70%':
                extensionField = '0xB2010008'
            elif opKey == 'c80%':
                extensionField = '0xCC010008'
            elif opKey == 'c90%':
                extensionField = '0xE5010008'
            elif opKey == 'c100%':
                extensionField = '0xFE010008'
            keyStr = ''
            if i == 0:
                keyStr = cmd[0]
                scenParse = keyStr.split('@')
                scenAddress = scenParse[0]
                scenAddr = scenAddress
                sNID = macMap[scenAddress]['nodeId']
                # sNID = sNodeId
                sEID = scenParse[1]
                # sEID = sEndPID
                scenID = '0x0%s' % sEID
                scenName = '%s' % sEID

                keyStr = cmd[1]
                scenParse = keyStr.split('@')
                scenAddress = scenParse[0]
                devAddr = scenAddress
                dNID = macMap[scenAddress]['nodeId']
                # dNID = sNodeId
                dEID = scenParse[1]
                # dEID = sEndPID

                # unbind
                cluster = ''
                # 窗帘场景
                if opKey[0] == 'c':
                    cluster = '0x0008'
                # 灯场景
                else:
                    cluster = '0x0006'

                stoDevUnStr = '{"commands":[{"commandcli":"zdo unbind unicast %s {%s} %s %s {%s} %s"}]}' \
                              % (sNID, scenAddr[2:], sEID, cluster, devAddr[2:], dEID)
                print "CreateScen:unbind:stodev:%s" % stoDevUnStr
                self.application.mqttClient.publish(COMMAND_SI, stoDevUnStr, qos=0, retain=False)

                devToSUnStr = '{"commands":[{"commandcli":"zdo unbind unicast %s {%s} %s %s {%s} %s"}]}' \
                              % (dNID, devAddr[2:], dEID, cluster, scenAddr[2:], sEID)
                print "CreateScen:unbind:devtos:%s" % devToSUnStr
                self.application.mqttClient.publish(COMMAND_SI, devToSUnStr, qos=0, retain=False)

                #create scenario
                self.application.mqttClient.publish(COMMAND_SI, model1, qos=0, retain=False)
                sendStr = model2 % (sNID, sEID)
                self.application.mqttClient.publish(COMMAND_SI, sendStr, qos=0, retain=False)
                msgStr = model3 % (scenID, scenName, extensionField)
                self.application.mqttClient.publish(COMMAND_SI, msgStr, qos=0, retain=False)
                self.application.mqttClient.publish(COMMAND_SI, sendStr, qos=0, retain=False)

                self.application.mqttClient.publish(COMMAND_SI, model1, qos=0, retain=False)
                sendStr = model2 % (dNID, dEID)
                self.application.mqttClient.publish(COMMAND_SI, sendStr, qos=0, retain=False)
                msgStr = model3 % (scenID, scenName, extensionField)
                self.application.mqttClient.publish(COMMAND_SI, msgStr, qos=0, retain=False)
                self.application.mqttClient.publish(COMMAND_SI, sendStr, qos=0, retain=False)

            else:
                # keyStr = cmd[1]
                # scenParse = keyStr.split('@')
                # scenAddress = scenParse[0]
                # sNodeId = macMap[scenAddress]['nodeId']
                # sEndPID = scenParse[1]

                keyStr = cmd[1]
                scenParse = keyStr.split('@')
                scenAddress = scenParse[0]
                devAddr = scenAddress
                sNodeId = macMap[scenAddress]['nodeId']
                dNID = sNodeId
                sEndPID = scenParse[1]
                dEID = sEndPID
                print "scen key str:%s" % keyStr

                keyStr = cmd[0]
                scenParse = keyStr.split('@')
                scenAddress = scenParse[0]
                scenAddr = scenAddress
                sNodeId = macMap[scenAddress]['nodeId']
                sNID = sNodeId
                sEndPID = scenParse[1]
                sEID = sEndPID

                # unbind
                cluster = ''
                # 窗帘场景
                if opKey[0] == 'c':
                    cluster = '0x0008'
                # 灯场景
                else:
                    cluster = '0x0006'
                stoDevUnStr = '{"commands":[{"commandcli":"zdo unbind unicast %s {%s} %s %s {%s} %s"}]}' \
                              % (sNID, scenAddr[2:], sEID, cluster, devAddr[2:], dEID)
                print "CreateScen:unbind:stodev:%s" % stoDevUnStr
                self.application.mqttClient.publish(COMMAND_SI, stoDevUnStr, qos=0, retain=False)
                devToSUnStr = '{"commands":[{"commandcli":"zdo unbind unicast %s {%s} %s %s {%s} %s"}]}' \
                              % (dNID, devAddr[2:], dEID, cluster, scenAddr[2:], sEID)
                print "CreateScen:unbind:devtos:%s" % devToSUnStr
                self.application.mqttClient.publish(COMMAND_SI, devToSUnStr, qos=0, retain=False)


                #create scenario
                self.application.mqttClient.publish(COMMAND_SI, model1, qos=0, retain=False)
                sendStr = model2 % (dNID, dEID)
                self.application.mqttClient.publish(COMMAND_SI, sendStr, qos=0, retain=False)
                msgStr = model3 % (scenID, scenName, extensionField)
                self.application.mqttClient.publish(COMMAND_SI, msgStr, qos=0, retain=False)
                self.application.mqttClient.publish(COMMAND_SI, sendStr, qos=0, retain=False)

                # keyStr = cmd[0]
                # scenParse = keyStr.split('@')
                # scenAddress = scenParse[0]
                # scenAddr = scenAddress
                # sNodeId = macMap[scenAddress]['nodeId']
                # sNID = sNodeId
                # sEndPID = scenParse[1]
                # sEID = sEndPID
                #
                # # unbind
                # stoDevUnStr = '{"commands":[{"commandcli":"zdo unbind unicast %s {%s} %s 0x0006 {%s} %s"}]}' \
                #               % (sNID, scenAddr, sEID, devAddr, dEID)
                # print "CreateScen:unbind:stodev:%s" % stoDevUnStr
                # self.application.mqttClient.publish(COMMAND_SI, stoDevUnStr, qos=0, retain=False)
                # devToSUnStr = '{"commands":[{"commandcli":"zdo unbind unicast %s {%s} %s 0x0006 {%s} %s"}]}' \
                #               % (dNID, devAddr, dEID, scenAddr, sEID)
                # print "CreateScen:unbind:devtos:%s" % devToSUnStr
                # self.application.mqttClient.publish(COMMAND_SI, devToSUnStr, qos=0, retain=False)


@route(r'/command', name='command')
class CommandHandler(RequestHandler):
    # cmd 格式
    # xxx @ xxx @ xxx
    # 类型  ep    新值
    #
    # 类型：
    #      开关 - 1一路,2二路,3三路,8指示灯模式命令,20定时（同插座）
    #           定时命令:state
    #                   xx - xx
    #                  时间  设置
    #                    * - *
    #                   取消定时
    #
    #      窗帘 - 11一路,12二路,13三路,10窗帘命令，21窗帘定时
    #           窗帘命令：state
    #                   1-启动校准
    #                   0-结束校准
    #           定时：
    #                   时间 -> 定时
    #                   *    -> 取消定时
    def get(self):
        print "cmd pub msg"
        # {"Address": "000D6F0011002B5F", "GroupId": "0",
        #  "EndpointId": "1", "CommandType": "0106",
        #  "Command": {"Type": "1101", "State": "1"}}
        address = self.get_argument("address", None)
        cmd = self.get_argument("cmd", None)
        cmdParse = cmd.split("@")


        print "address:%s" % address
        msg = {}
        msg['EndpointId'] = cmdParse[1]
        # msg['Address'] = address
        # msg['GroupId'] = '0'
        # msg['CommandType'] = '0106'
        #
        # subCmd = {}
        # subCmd['Type'] = '110' + cmdParse[0]
        # subCmd['State'] = cmdParse[2]
        # msg['Command'] = subCmd
        # msgStr = json.dumps(msg)
        # print "cmd:%s" % msgStr
        # self.application.mqttClient.publish(COMMAND_TOPIC, msgStr, qos=0, retain=False)
        btnType = cmdParse[0]
        state = cmdParse[2]
        address = address[2:]
        if btnType == '8':
            self.led(address, state)
            return

        if btnType == '6':
            self.lockControl(address, state)
            return

        # 窗帘命令
        # 10 : 校准
        # 11 : 1位窗帘位置控制
        # 12 : 2位窗帘位置控制
        if btnType == '10' or btnType == '11' or btnType == '12':
            #print "________________________________________endpoint:",msg['EndpointId']
            self.curtainControl(btnType, address, state, msg['EndpointId'])
            return



        # 开关插座定时
        if btnType == '20':
            print ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>", state
            timarg1 = state.split("-")
            timval1 = timarg1[0]
            timset1 = timarg1[1]

            # 取消定时
            if state == '*-*':
                print "取消定时---------------------------"
                model = '{"commands":[{"commandcli":"zcl mfg-code 0x0000"}]}'
                self.application.mqttClient.publish(COMMAND_SI, model, qos=0, retain=False)
                model1 = '{"commands":[{"commandcli":"zcl on-off on"}]}'
                self.application.mqttClient.publish(COMMAND_SI, model1, qos=0, retain=False)
                model2 = '{"commands":[{"commandcli":"plugin device-table send {%s} 0x%s"}]}' % (
                address, msg['EndpointId'])
                self.application.mqttClient.publish(COMMAND_SI, model2, qos=0, retain=False)

            if timset1 == '0' or timset1 == '1':
                print "发送粒度设置---------------------------"
                # 发送粒度设置
                model = '{"commands":[{"commandcli":"zcl mfg-code 0x1254"}]}'
                self.application.mqttClient.publish(COMMAND_SI, model, qos=0, retain=False)
                model1 = '{"commands":[{"commandcli":"zcl global write 0xfc56 0x0004 0x20 {0%s}"}]}' %(timset1)
                self.application.mqttClient.publish(COMMAND_SI, model1, qos=0, retain=False)
                model2 = '{"commands":[{"commandcli":"plugin device-table send {%s} 0x%s"}]}' % (address, msg['EndpointId'])
                self.application.mqttClient.publish(COMMAND_SI, model2, qos=0, retain=False)

            if timval1 != '*':
                print "发送定时---------------------------"
                # 发送定时
                model = '{"commands":[{"commandcli":"zcl mfg-code 0x0000"}]}'
                self.application.mqttClient.publish(COMMAND_SI, model, qos=0, retain=False)
                model1 = '{"commands":[{"commandcli":"zcl on-off ontimedoff 0 %s 0"}]}' % (timval1)
                self.application.mqttClient.publish(COMMAND_SI, model1, qos=0, retain=False)
                model2 = '{"commands":[{"commandcli":"plugin device-table send {%s} 0x%s"}]}' % (
                address, msg['EndpointId'])
                self.application.mqttClient.publish(COMMAND_SI, model2, qos=0, retain=False)

            return

        # 窗帘定时
        if btnType == '21':
            print ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>", state

            # 取消定时
            if state == "*":
                pass
            # 发送定时
            else:
                ctarg = state.split("-")
                tim_ct = ctarg[0]
                level = ctarg[1]
                buf_int10 = int(tim_ct, 10)
                buf_str16 = str(hex(buf_int10))
                buf_str16 = "0000000%s" %(buf_str16[2:])
                print ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>buf_str16: ", buf_str16
                len_str = len(buf_str16)
                buf_str = ""
                buf_str = buf_str16[len_str-8:]
                print ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>buf_str: ", buf_str
                buf_str = buf_str[6:] + buf_str[4:6] + buf_str[2:4] + buf_str[0:2]


                model = '{"commands":[{"commandcli":"zcl mfg-code 0x1254"}]}'
                self.application.mqttClient.publish(COMMAND_SI, model, qos=0, retain=False)
                model1 = '{"commands":[{"commandcli":"zcl simon extend {0102010111%s08000000%s}"}]}' % (buf_str, level)
                self.application.mqttClient.publish(COMMAND_SI, model1, qos=0, retain=False)
                model2 = '{"commands":[{"commandcli":"plugin device-table send {%s} 0x%s"}]}' % (
                    address, msg['EndpointId'])
                self.application.mqttClient.publish(COMMAND_SI, model2, qos=0, retain=False)
            return

        # 窗帘定时余量
        if btnType == '22':
            model = '{"commands":[{"commandcli":"zcl mfg-code 0x1254"}]}'
            self.application.mqttClient.publish(COMMAND_SI, model, qos=0, retain=False)
            model1 = '{"commands":[{"commandcli":"zcl simon extend {0101010111}"}]}'
            self.application.mqttClient.publish(COMMAND_SI, model1, qos=0, retain=False)
            model2 = '{"commands":[{"commandcli":"plugin device-table send {%s} 0x%s"}]}' % (
                address, msg['EndpointId'])
            self.application.mqttClient.publish(COMMAND_SI, model2, qos=0, retain=False)
            return


        if state == '1':
            cmd = 'on'
        else:
            cmd = 'off'
        # model = '{"commands":[{"command":"zcl on-off %s"},{"command":"plugin device-table send {%s} 0x%s"}]}' % (cmd, address, msg['EndpointId'])


        if msg['EndpointId'] == '0':
            num = int(cmdParse[0]) + 1
            for i in range(1, num):
                model = '{"commands":[{"command":"zcl on-off %s"},{"command":"plugin device-table send {%s} 0x%s"}]}' % (cmd, address, i)
                print "loop:model:%s" % model
                self.application.mqttClient.publish(COMMAND_SI, model, qos=0, retain=False)
        else:
            print '____________________________________________'
            model = '{"commands":[{"command":"zcl on-off %s"},{"command":"plugin device-table send {%s} 0x%s"}]}' % (cmd, address, msg['EndpointId'])
            print "single:model:%s" % model
            self.application.mqttClient.publish('gw/90FD9FFFFE19BB60/commands', model, qos=0, retain=False)
            print COMMAND_SI,'__________________________'


    # 窗帘
    def curtainControl(self, btnType, address, state, ep):
        # btnType           10，11，12
        # state             参数
        # address           ID
        # ep                EP
        macMap = self.application.macMap
        address = '0x%s' % address
        nodeId = macMap[address]['nodeId']
        model1 = '{"commands": [{"commandcli": "zcl mfg-code 0"}]}'
        self.application.mqttClient.publish(COMMAND_SI, model1, qos=0, retain=False)
        # 1位窗帘
        if btnType == '11':

            if int(("0x%s" %state), 16) < 0x100:
                model2 = '{"commands": [{"commandcli": "zcl on-off on"},{"commandcli": "send %s 1 1"}]}' % (nodeId)
                self.application.mqttClient.publish(COMMAND_SI, model2, qos=0, retain=False)
                model3 = '{"commands": [{"commandcli": "zcl level-control mv-to-level 0x%s 0 0 0"},{"commandcli": "send %s 1 1"}]}' % (state, nodeId)
                self.application.mqttClient.publish(COMMAND_SI, model3, qos=0, retain=False)
                #model2 = '{"commands": [{"commandcli": "zcl on-off off"},{"commandcli": "send %s 1 %s"}]}' % (nodeId, ep)
                #self.application.mqttClient.publish(COMMAND_SI, model2, qos=0, retain=False)

                #self.application.macMap[address]['curtainLevel'][str(int(ep,10))] = "0x%s" %state
                #print "窗帘控制[位置]：", self.application.macMap[address]['curtainLevel'][str(int(ep,10))]

        # 2位窗帘
        elif btnType == '12':
            if int(("0x%s" %state), 16) < 0x100:
                model2 = '{"commands": [{"commandcli": "zcl on-off on"},{"commandcli": "send %s 1 %s"}]}' % (nodeId, ep)
                self.application.mqttClient.publish(COMMAND_SI, model2, qos=0, retain=False)
                model3 = '{"commands": [{"commandcli": "zcl level-control mv-to-level 0x%s 0 0 0"},{"commandcli": "send %s 1 %s"}]}' % (state, nodeId, ep)
                self.application.mqttClient.publish(COMMAND_SI, model3, qos=0, retain=False)
                #model2 = '{"commands": [{"commandcli": "zcl on-off off"},{"commandcli": "send %s 1 %s"}]}' % (nodeId, ep)
                #self.application.mqttClient.publish(COMMAND_SI, model2, qos=0, retain=False)

                #self.application.macMap[address]['curtainLevel'][ep] = int(("0x%s" %state), 16)
                #print "窗帘控制[位置]：", self.application.macMap[address]['curtainLevel']

            # 一键开合
            elif state == '101'or state == '100':
                print "__________________________________________________一件开合!!!"
                if state == '101':
                    pos = 'FE'
                else:
                    pos = '01'

                for i in [0, 1]:
                    model2 = '{"commands": [{"commandcli": "zcl on-off on"},{"commandcli": "send %s 1 %s"}]}' % (nodeId, i + 1)
                    self.application.mqttClient.publish(COMMAND_SI, model2, qos=0, retain=False)
                    model3 = '{"commands": [{"commandcli": "zcl level-control mv-to-level 0x%s 0 0 0"},{"commandcli": "send %s 1 %s"}]}' % (pos, nodeId, i + 1)
                    self.application.mqttClient.publish(COMMAND_SI, model3, qos=0, retain=False)
                    #model2 = '{"commands": [{"commandcli": "zcl on-off off"},{"commandcli": "send %s 1 %s"}]}' % (nodeId, i + 1)
                    #self.application.mqttClient.publish(COMMAND_SI, model2, qos=0, retain=False)

                    #self.application.macMap[address]['ep%s' %(i)]['curtainLevel'] = int(("0x%s" %pos), 16)
                    #print "窗帘控制[位置]：", self.application.macMap[address]['curtainLevel']



        # 其他命令
        elif btnType == '10':
            # 启动校准
            if state == '1':
                # 进入configuration模式
                model2 = '{"commands": [{"commandcli": "zcl global write 0x0100 0x0011 0x30 {01}"},{"commandcli": "send %s 1 %s"}]}' %(nodeId, ep)
                self.application.mqttClient.publish(COMMAND_SI, model2, qos=0, retain=False)
                print "窗帘控制[启动校准]"
            # 结束校准
            elif state == '0':
                # 进入configuration模式
                model2 = '{"commands": [{"commandcli": "zcl global write 0x0100 0x0011 0x30 {00}"},{"commandcli": "send %s 1 %s"}]}' %(nodeId, ep)
                self.application.mqttClient.publish(COMMAND_SI, model2, qos=0, retain=False)
                print "窗帘控制[结束校准]"




    def led(self, address, state):
        macMap = self.application.macMap
        address = '0x%s' % address
        print "led:address:%s" % address
        nodeId = macMap[address]['nodeId']
        print "led:nodeId:%s" % nodeId
        model1 = '{"commands": [{"commandcli": "zcl mfg-code 0x1254 "}]}'
        print "led:model1:%s" % model1
        self.application.mqttClient.publish(COMMAND_SI, model1, qos=0, retain=False)
        model2 = '{"commands": [{"commandcli": "zcl global write 0xFC56 0x0000 0x20 {0%s}"}]}' % state
        print "led:model2:%s" % model2
        self.application.mqttClient.publish(COMMAND_SI, model2, qos=0, retain=False)
        model3 = '{"commands": [{"commandcli": "send %s 1 1"}]}' % nodeId
        print "led:model3:%s" % model3
        self.application.mqttClient.publish(COMMAND_SI, model3, qos=0, retain=False)
        if state == '0':
            print "change led to status"
            self.application.macMap[address]['lightStatus'] = True
        else:
            print "change led to location"
            self.application.macMap[address]['lightStatus'] = False

    def lockControl(self, address, state):
        macMap = self.application.macMap
        address = '0x%s' % address
        print "lockControl:address:%s" % address
        nodeId = macMap[address]['nodeId']
        print "lockControl:nodeId:%s" % nodeId
        model1 = '{"commands": [{"commandcli": "zcl mfg-code 0x1254 "}]}'
        print "lockControl:model1:%s" % model1
        self.application.mqttClient.publish(COMMAND_SI, model1, qos=0, retain=False)
        model2 = '{"commands": [{"commandcli": "zcl global write 0xFC56 0x0001 0x20 {0%s}"}]}' % state
        print "lockControl:model2:%s" % model2
        self.application.mqttClient.publish(COMMAND_SI, model2, qos=0, retain=False)
        model3 = '{"commands": [{"commandcli": "send %s 1 1"}]}' % nodeId
        print "lockControl:model3:%s" % model3
        self.application.mqttClient.publish(COMMAND_SI, model3, qos=0, retain=False)

