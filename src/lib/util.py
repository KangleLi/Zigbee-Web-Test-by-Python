#!/usr/bin/env python
#coding=utf8

def setting_from_object(obj):
    setting = dict()
    for key in dir(obj):
        if key.isupper():
            setting[key.lower()] = getattr(obj, key)
    return setting
    return setting

def find_subclasses(klass, include_self=False):
    accum = []
    for child in klass.__subclasses__():
        accum.extend(find_subclasses(child, True))
    if include_self:
        accum.append(klass)
    return accum