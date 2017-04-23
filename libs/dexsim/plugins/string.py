# coding:utf-8

import hashlib
from json import JSONEncoder
import re

from libs.dexsim.plugin import Plugin


__all__ = ["STRING"]


class STRING(Plugin):

    name = "STRING"
    version = '0.0.3'

    def __init__(self, driver, methods, smali_files):
        Plugin.__init__(self, driver, methods, smali_files)

    def run(self):
        print('run Plugin: %s' % self.name, end=' -> ')
        self._process()

    def _process(self):
        #const-string
        #invoke-static
        #move-result are the basically needed
        p = re.compile('const-string.*?' + self.INVOKE_STATIC_NORMAL + '\s+' + self.MOVE_RESULT_OBJECT, re.DOTALL)

        self.json_list = []
        self.target_contexts = {}
        for mtd in self.methods:
            for i in p.finditer(mtd.body):
                block = i.group()

                #args = self.get_arguments(None, line, 'java.lang.String')
                funcInfo = self.get_func_info(block)
                if not funcInfo['params']:
                    continue
                args = self.get_params(block, funcInfo['params'], funcInfo['paramsType'])
                if not args:
                    continue

                cls_name, mtd_name, rtn_name = self.get_clz_mtd_rtn_name(block)

                json_item = self.get_json_item(cls_name, mtd_name, args)
                self.append_json_item(json_item, mtd, block, rtn_name)
        self.optimize()