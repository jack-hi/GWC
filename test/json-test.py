#!/usr/bin/python3
# -*- coding: utf-8 -*-

from json import loads, dumps
# a = '{"LogId":0,"Wx_DoorName":"大门1","Wx_DrNumInFlc":2,"Wx_DrShowFlr":"1F","Wx_FlcNum":101,"Wx_buildNum":"F01213"}'
# print(a)
#
# j = loads(a)
# print(j)
#
#
# d = dumps(j)
# print(d)


dict2json = lambda x: dumps(x)
json2dict = lambda x: loads(x)


if __name__ == '__main__':
    a = dict()
    a['id'] = 10
    a['name'] = "name"
    j = dict2json(a)
    print(j)
    print(type(j))
    d = json2dict(j)
    print(d)
    print(type(d))

    jj = '{"ErrMsg": "", "IsSuccess": true, "OperationTime": "2019-03-09 16:26:57", "Remark": "", "ReplyCommand": 1, "Wx_FlcNum": 120, "Wx_buildNum": "F1021"}'
    print(json2dict(jj))