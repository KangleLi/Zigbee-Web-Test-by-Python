#!/usr/bin/env python
#coding=utf8

import os
from jinja2 import Environment, FileSystemLoader
import setting
from lib.util import setting_from_object


settings = setting_from_object(setting)

settings.update({
        'template_path':os.path.join(os.path.dirname(__file__), 'template'),
        'static_path':os.path.join(os.path.dirname(__file__), 'style'),
        'upload_path':os.path.join(os.path.dirname(__file__), 'upload'),
        'cookie_secret':"SZUzonpBQIuXE3yKBtWPre2N5AS7jEQKv0Kioj9iKT0=",
        'login_url':'/signin',
        "xsrf_cookies": True,
        'autoescape':None
    })

memcachedb = None

bcc = None


jinja_environment = Environment(
            loader = FileSystemLoader(settings['template_path']),
            bytecode_cache = bcc,
            auto_reload = settings['debug'],
            autoescape = False)

