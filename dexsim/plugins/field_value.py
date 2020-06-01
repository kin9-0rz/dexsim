import ast
import logging
import os
import re
import tempfile
from json import JSONEncoder

import yaml
from smafile import smali2java
from smaliemu.emulator import Emulator

from dexsim import var
from dexsim.plugin import Plugin

PLUGIN_CLASS_NAME = "FieldValue"


class FieldValue(Plugin):
    """
    针对那些<clint>中自动初始化的字符串类型字段ield，
    获取字符串类型的Field，直接获取Field的值。

    这个插件只需要执行一次
    """
    name = "FieldValue"
    enabled = True
    tname = None
    index = 0

    ONE_TIME = True
    ot_flag = False

    def __init__(self, driver, smalidir):
        Plugin.__init__(self, driver, smalidir)

    def run(self):
        if self.ot_flag:
            return
        if self.ONE_TIME:
            self.ot_flag = True
        print('Run', __name__, end=' ', flush=True)
        self.__process()

    def __process(self):
        self.json_list = {
            'type': 'field',
            'data': []
        }
        for sf in self.smalidir:
            if self.skip(sf):
                continue

            class_name = smali2java(sf.get_class())
            counter = 0
            for f in sf.get_fields():
                if 'Ljava/lang/String;' != f.get_type():
                    continue

                if f.get_value():
                    continue

                if not f.get_is_static():
                    continue

                # 格式:如果ID是FieldValue，则直接取对应的Field，不执行解密方法
                data = {
                    'className': class_name,
                    'fieldName': f.get_name(),
                }
                print(data)
                resutl = self.driver.rpc_static_field(data)
                print(resutl)

            # 没静态变量，则跳过
            if counter < 1:
                continue


    def skip(self, sf):
        '''
        跳过没静态构造函数的类

        因为没有需要初始化的变量，不做任何处理；而且，有可能导致一些奇怪的错误。
        '''
        #
        m = sf.get_method('<clinit>')
        if not m:
            return True

        m = sf.get_method('<init>')
        # 没有构造函数，不需要跳过
        if not m:
            return False
        # java.lang.RuntimeException:
        # Can't create handler inside thread that has not called
        # Looper.prepare()
        if 'Landroid/os/Handler;-><init>' in m.get_body():
            return True
        return False

    def optimize(self):
        """
        把Field的值，写回到smali中

        因为Field本来就是唯一，所以，不需要ID
        """
        if not self.json_list:
            return

        jsons = JSONEncoder().encode(self.json_list)

        outputs = {}
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tfile:
            tfile.write(jsons)
        outputs = self.driver.decode(tfile.name)
        os.unlink(tfile.name)

        if not outputs:
            return False

        if isinstance(outputs, str):
            return False

        if var.is_debug:
            for k, v in outputs.items():
                print(k, v)

        for sf in self.smalidir:
            clz = smali2java(sf.get_class())
            if clz not in outputs.keys():
                continue

            for item in outputs[clz].items():
                self.update_field(sf, item[0], item[1])

        self.make_changes = True
        self.smali_files_update()
        self.clear()

    def update_field(self, sf, fieldname, value):
        """Short summary.

        Args:
            sf (SmaliFeild): Smali字段类
            fieldname (String): 字段名
            value (Object): 字段值（数值、字符串、列表等，根据实际类型赋值）

        Returns:
            None
        """
        for f in sf.get_fields():
            if f.get_name() != fieldname:
                continue
            if '[Ljava/lang/String;' == f.get_type():
                if 'null' in value:
                    return
                value = ast.literal_eval(value)
                f.set_value(value)
            else:
                f.set_value(value)
