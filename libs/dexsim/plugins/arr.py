# coding:utf-8
import hashlib
from json import JSONEncoder
import re

from libs.dexsim.plugin import Plugin

__all__ = ["Arr"]

class Arr(Plugin):

    name = "ARRAY"
    version = '0.0.2'
    description = '参数类型 [B'
    enabled = False

    def __init__(self, driver, methods, smali_files):
        Plugin.__init__(self, driver, methods, smali_files)

    def run(self):
        print('run Plugin: %s' % self.name, end=' -> ')
        self._process_byte_arr()
        self._process_int_arr()

    def _process_byte_arr(self):
        '''
            const/16 v2, 0x1a
            new-array v0, v2, [B
            fill-array-data v0, :array_1e
            invoke-static {v0}, La/b/c;->func([B)Ljava/lang/String;
            move-result-object v0

            ==>

            const-string v0, "decode string"
        '''
        invoke_ptn = self.get_invoke_pattern('\[B')
        ptn = self.NEW_BYTE_ARRAY + self.FILL_ARRAY_DATA + invoke_ptn + self.MOVE_RESULT_OBJECT
        print(ptn)
        p1 = re.compile(ptn)

        self.json_list = []
        self.target_contexts = {}

        for mtd in self.methods:
            for i in p1.finditer(mtd.body):
                line = i.group()

                args = self.get_arguments(mtd.body, line, '[B')

                if not args:
                    continue

                cls_name, mtd_name, rtn_name = self.get_clz_mtd_rtn_name(line)

                json_item = self.get_json_item(cls_name, mtd_name, args)

                self.append_json_item(json_item, mtd, line, rtn_name)

        self.optimize()


    def _process_int_arr(self):
        '''
            const/16 v2, 0x1a
            new-array v0, v2, [I
            fill-array-data v0, :array_1e
            invoke-static {v0}, La/b/c;->func([I)Ljava/lang/String;
            move-result-object v0

            ==>

            const-string v0, "decode string"
        '''
        invoke_ptn = self.get_invoke_pattern('\[I')
        ptn = self.NEW_INT_ARRAY + self.FILL_ARRAY_DATA + invoke_ptn + self.MOVE_RESULT_OBJECT
        print(ptn)
        p1 = re.compile(ptn)

        self.json_list = []
        self.target_contexts = {}

        for mtd in self.methods:
            for i in p1.finditer(mtd.body):
                line = i.group()
                args = self.get_arguments(mtd.body, line, '[I')

                if not args:
                    continue

                cls_name, mtd_name, rtn_name = self.get_clz_mtd_rtn_name(line)

                json_item = self.get_json_item(cls_name, mtd_name, args)

                self.append_json_item(json_item, mtd, line, rtn_name)

        self.optimize()
