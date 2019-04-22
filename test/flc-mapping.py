#!/usr/bin/python3
# -*- coding: utf-8 -*-

from redis import Redis

class FLCMapping:
    hash_name = "FLCMapping"
    def __init__(self, host='localhost', password=None):
        self.redis = Redis(host=host, password=password)

    def get_mappings(self):
        ret = dict()
        for k in self.redis.hkeys(self.hash_name):
            ret[k.decode()] = self.get_mapping(k).decode()

        return ret

    def get_mapping(self, dev):
        return self.redis.hget(self.hash_name, dev)

    def set_mapping(self, dev, target):
        self.redis.hset(self.hash_name, dev, target)
        self.redis.save()

    def set_mappings(self, mapping_dict):
        self.redis.hmset(self.hash_name, mapping_dict)
        self.redis.save()

    def del_mapping(self, dev):
        self.redis.hdel(self.hash_name, dev)
        self.redis.save()

    def del_mappings(self):
        keys = (k.decode() for k in self.redis.hkeys(self.hash_name))
        self.redis.hdel(self.hash_name, *keys)
        self.redis.save()


if __name__ == '__main__':
    fm = FLCMapping()
    fm.set_mappings({101:"102", 102:"103", 103:"104", 104:"105"})

    print(fm.get_mappings())
    # fm.del_mappings()
    # print(fm.get_mappings())
