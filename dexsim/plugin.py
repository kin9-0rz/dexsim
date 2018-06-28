"""
插件的基类。
- 解密插件必须继承这个类。
- 解密插件必须实现run方法。
"""
import hashlib
import logging
import os
import re
import tempfile
from abc import abstractmethod
from json import JSONEncoder

from smaliemu.emulator import Emulator
from timeout3 import timeout

logger = logging.getLogger(__name__)


class Plugin(object):
    """
    解密插件基类
    """
    name = 'Plugin'
    description = ''
    version = ''
    enabled = True
    index = 0 # 插件执行顺序；最小值为0，数值越大，执行越靠后。

    # const/16 v2, 0x1a
    CONST_NUMBER = r'const(?:\/\d+) [vp]\d+, (-?0x[a-f\d]+)\s+'
    # ESCAPE_STRING = '''"(.*?)(?<!\\\\)"'''
    ESCAPE_STRING = '"(.*?)"'
    # const-string v3, "encode string"
    CONST_STRING = r'const-string [vp]\d+, ' + ESCAPE_STRING + '.*'
    # move-result-object v0
    MOVE_RESULT_OBJECT = r'move-result-object ([vp]\d+)'
    # new-array v1, v1, [B
    NEW_BYTE_ARRAY = r'new-array [vp]\d+, [vp]\d+, \[B\s+'
    # new-array v1, v1, [B
    NEW_INT_ARRAY = r'new-array [vp]\d+, [vp]\d+, \[I\s+'
    # new-array v1, v1, [B
    NEW_CHAR_ARRAY = r'new-array [vp]\d+, [vp]\d+, \[C\s+'
    # fill-array-data v1, :array_4e
    FILL_ARRAY_DATA = r'fill-array-data [vp]\d+, :array_[\w\d]+\s+'

    ARRAY_DATA_PATTERN = r':array_[\w\d]+\s*.array-data[\w\W\s]+.end array-data'

    # [{'className':'', 'methodName':'', 'arguments':'', 'id':''}, ..., ]
    json_list = []
    # [(mtd, old_content, new_content), ..., ]
    target_contexts = {}
    #
    data_arraies = {}
    # smali methods witch have been update
    smali_mtd_updated_set = set()

    def __init__(self, driver, smalidir):
        self.make_changes = False
        self.driver = driver
        self.smalidir = smalidir
        # self.smali_files = smali_files

        self.emu = Emulator()
        self.emu2 = Emulator()

    # def get_return_variable_name(self, line):
    #     mro_statement = re.search(self.MOVE_RESULT_OBJECT, line).group()
    #     return mro_statement[mro_statement.rindex(' ') + 1:]

    @timeout(1)
    def pre_process(self, snippet):
        """
        smaliemu 处理sget等获取类的变量时，是直接从变量池中取等。
        所以，对于这些指令，可以预先初始化。

        先执行Feild Value插件，对类的成员变量进行解密，再进行处理。

        TODO 其他指令，其他参数
        """
        args = {}
        # sget-object v0, clz_name;->field_name:Ljava/util/List;
        # 能够作为参数的值，数字、字符串、数组等；而不是其他
        for line in snippet:
            if 'sget' not in line:
                continue

            field_desc = line.split()[-1]
            try:
                field = self.smalidir.get_field(field_desc)
                if not field:
                    continue
            except TypeError as ex:
                logger.warning(ex)
                logger(field_desc)
                continue

            value = field.get_value()
            if not value:
                continue

            args.update({field_desc: value})

        return args

    @staticmethod
    def convert_args(typ8, value):
        """
        根据参数类型，把参数转换为适合Json保存的格式。
        """
        if value is None:
            return None

        if typ8 == 'I':
            if not isinstance(value, int):
                return None
            return 'I:' + str(value)

        if typ8 == 'B':
            if not isinstance(value, int):
                return None
            return 'B:' + str(value)

        if typ8 == 'S':
            if not isinstance(value, int):
                return None
            return 'S:' + str(value)

        if typ8 == 'C':
            # don't convert to char, avoid some unreadable chars.
            return 'C:' + str(value)

        if typ8 == 'Ljava/lang/String;':
            if not isinstance(value, str):
                return None

            import codecs
            item = codecs.getdecoder('unicode_escape')(value)[0]
            args = []
            for i in item.encode("UTF-8"):
                args.append(i)
            return "java.lang.String:" + str(args)

        if typ8 == '[B':
            if not isinstance(value, list):
                return None
            byte_arr = []
            for item in value:
                if item == '':
                    item = 0
                byte_arr.append(item)
            return '[B:' + str(byte_arr)

        if typ8 == '[C':
            if not isinstance(value, list):
                return None
            byte_arr = []
            for item in value:
                if item == '':
                    item = 0
                byte_arr.append(item)
            return '[C:' + str(byte_arr)

        logger.warning('不支持该类型 %s %s', typ8, value)

    @timeout(3)
    def get_vm_variables(self, snippet, args, rnames):
        """
        snippet : smali 代码
        args    ：方法参数
        rnames  ：寄存器

        获取当前vm的变量

        """
        # 原本想法是，行数太多，执行过慢；而参数一般在前几行
        # 可能执行5句得倒的结果，跟全部执行的不一样
        # TODO 有一定的几率，得到奇怪的参数，导致解密结果异常
        self.emu2.call(snippet[-5:], args=args, thrown=False)
        result = self.varify_argments(self.emu2.vm.variables, rnames)
        if result:
            return self.emu2.vm.variables

        self.emu2.call(snippet, args=args, thrown=False)
        result = self.varify_argments(self.emu2.vm.variables, rnames)
        if result:
            return self.emu2.vm.variables

    @staticmethod
    def varify_argments(variables, arguments):
        """
        variables ：vm存放的变量
        arguments ：smali方法的参数
        验证smali方法的参数
        """
        for k in arguments:
            value = variables.get(k, None)
            if value is None:
                return False
        return True

    @staticmethod
    def get_json_item(cls_name, mtd_name, args):
        """
        json item 为一个json格式的解密对象。
        包含id、className、methodName、arguments。
        模拟器/手机会通过解析这个对象进行解密。
        """
        item = {'className': cls_name,
                'methodName': mtd_name,
                'arguments': args}
        item['id'] = hashlib.sha256(JSONEncoder().encode(item).encode(
            'utf-8')).hexdigest()
        return item

    def append_json_item(self, json_item, mtd, old_content, rtn_name):
        """
        往json list添加json解密对象
        json list 存放了所有的json格式解密对象。
        """
        mid = json_item['id']
        if rtn_name:
            new_content = 'const-string ' + rtn_name + ', "{}"'
        else:
            new_content = ('const-string v0, "Dexsim"\n'
                           'const-string v1, "{}"\n'
                           'invoke-static {v0, v1}, Landroid/util/Log;->d'
                           '(Ljava/lang/String;Ljava/lang/String;)I\n')

        if mid not in self.target_contexts:
            self.target_contexts[mid] = [(mtd, old_content, new_content)]
        else:
            self.target_contexts[mid].append((mtd, old_content, new_content))

        if json_item not in self.json_list:
            self.json_list.append(json_item)

    @abstractmethod
    def run(self):
        """
        插件执行逻辑
        插件必须实现该方法
        """
        pass

    def optimize(self):
        """
        smali 通用优化代码
        一般情况下，可以使用这个，插件也可以实现自己的优化方式。
        """
        if not self.json_list or not self.target_contexts:
            return

        jsons = JSONEncoder().encode(self.json_list)

        outputs = {}
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tfile:
            tfile.write(jsons)
        outputs = self.driver.decode(tfile.name)
        os.unlink(tfile.name)

        if not outputs:
            return

        if isinstance(outputs, str):
            return

        for key, value in outputs.items():
            if key not in self.target_contexts:
                logger.warning('not found %s', key)
                continue

            if value[0] == 'null':
                continue
            
            # json_item, mtd, old_content, rtn_name
            for item in self.target_contexts[key]:
                old_body = item[0].get_body()
                old_content = item[1]
                new_content = item[2].format(value[0])

                item[0].set_body(old_body.replace(old_content, new_content))
                item[0].set_modified(True)
                self.make_changes = True

        self.smali_files_update()
        self.clear()

    def clear(self):
        """
        每次解密完毕后，都需要清理。
        """
        self.json_list.clear()
        self.target_contexts.clear()

    def smali_files_update(self):
        '''
            write changes to smali files
        '''
        if self.make_changes:
            for sf in self.smalidir:
                sf.update()
