# coding:utf-8

import hashlib
from json import JSONEncoder
import re
import os
import yaml

from libs.dexsim.plugin import Plugin


__all__ = ["TEMPLET"]


class TEMPLET(Plugin):

    name = "TEMPLET"
    version = '0.0.1'
    enabled = True
    tname = None

    def __init__(self, driver, methods, smali_files):
        Plugin.__init__(self, driver, methods, smali_files)


    def run(self):
        print('run Plugin: %s' % self.name, end=' -> ')
        self.__load_templets()

    def __load_templets(self):
        print()
        templets_path = os.path.dirname(__file__)[:-7] + 'templets'
        for filename in os.listdir(templets_path):
            with open(templets_path + os.sep + filename) as f:
                datas = yaml.load(f.read())
                for item in datas:
                    for key in item:
                        self.tname = key
                        if not item[key]['enabled']:
                            print('Not Load templet:', self.tname)
                            continue
                        print('Load templet:', self.tname)
                        args = item[key]['args'].replace('\\', '')
                        reg = ''.join(item[key]['reg'])
                        self.__process(args, reg)

    def __process(self, args, reg):
        p = re.compile(reg)

        self.json_list = []
        for mtd in self.methods:
            for i in p.finditer(mtd.body):
                old_content = i.group()

                arguments = None
                if self.tname == 'byte_arr_sget':
                    arguments = self.get_arguments_from_clinit(i.groups()[1])
                else:
                    arguments = self.get_arguments(mtd.body, old_content, args)

                if not arguments:
                    continue

                cls_name, mtd_name, rtn_name = self.get_clz_mtd_rtn_name(old_content)

                json_item = self.get_json_item(cls_name, mtd_name, arguments)
                self.append_json_item(json_item, mtd, old_content, rtn_name)

        self.optimize()
