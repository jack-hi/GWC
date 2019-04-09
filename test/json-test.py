#!/usr/bin/python3
# -*- coding: utf-8 -*-

from json import loads, dumps
a = '{"LogId":0,"Wx_DoorName":"大门1","Wx_DrNumInFlc":2,"Wx_DrShowFlr":"1F","Wx_FlcNum":101,"Wx_buildNum":"F01213"}'
print(a)

j = loads(a)
print(j)


d = dumps(j)
print(d)