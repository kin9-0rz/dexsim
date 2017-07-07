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
                        if not item[key]['enabled']:
                            print('Not Load templet:', key)
                            continue
                        print('Load templet:', key)
                        args = item[key]['args'].replace('\\', '')
                        reg = ''.join(item[key]['reg'])
                        self.__process(args, reg)

    def __process(self, args, reg):
        p = re.compile(reg)

        self.json_list = []
        for mtd in self.methods:
            # if 'com/a/e;->a(Ljava/lang/String;Ljava/lang/String;IIII)Ljava/lang/String;' not in mtd.descriptor:
            #     continue

            for i in p.finditer(mtd.body):
                old_content = i.group()
                # FIXME 参数的检索方法
                # 有可能存在参数与调用函数之间，有其他代码，这样就无法匹配到了
                # 如果把参数和调用方法，分开匹配
                # 那么则会增加替换的难度
                #
                # 如果一定要用：
                # 定位的方法，采用行数定位的方法。
                # 1. 先匹配方法，得到所在的行
                # 2. 从当前行回溯，找参数
                # 3. 找到则获取参数，找不到，则继续匹配下一个函数
                #
                # 替换的时候
                # 如果解密成功，则直接删掉参数所在的行 —— 可以考虑保留
                # 直接替换调用函数所在的行(并非所有的代码，都有.old_content)

                arguments = self.get_arguments(mtd.body, old_content, args)

                if not arguments:
                    continue

                cls_name, mtd_name, rtn_name = self.get_clz_mtd_rtn_name(old_content)

                json_item = self.get_json_item(cls_name, mtd_name, arguments)
                self.append_json_item(json_item, mtd, old_content, rtn_name)
        self.optimize()
