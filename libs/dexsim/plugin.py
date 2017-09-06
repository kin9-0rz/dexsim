from json import JSONEncoder
import tempfile
import os
import hashlib
import re

from smaliemu.emulator import Emulator


class Plugin(object):
    name = 'Plugin'
    description = ''
    version = ''
    enabled = True

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

    def __init__(self, driver, methods, smalidir):
        self.make_changes = False
        self.driver = driver
        self.methods = methods
        self.smalidir = smalidir
        # self.smali_files = smali_files
        self.emu = Emulator()

    def get_arguments_from_clinit(self, field):
        sput_obj_prog = re.compile(r'([\w\W]+?)sput-object (v\d+), %s' %
                                   re.escape(field))
        arr_data_prog = re.compile(self.ARRAY_DATA_PATTERN)

        for smali_file in self.smali_files:
            if smali_file.class_name in field:
                continue

            for mtd in smali_file.methods:
                arr = []
                if mtd.name == '<clinit>':
                    matchs = sput_obj_prog.search(mtd.body).groups()
                    snippet = matchs[0]

                    arr = re.split(r'\n+', snippet)[:-1]
                    arr.append('return-object %s' % matchs[1])
                    result = arr_data_prog.search(mtd.body)
                    if result:
                        array_data_content = re.split(r'\n+', result.group())
                        arr.extend(array_data_content)

                    arr_data = self.emu.call(arr)
                    if self.emu.vm.exceptions:
                        break

                    arguments = []
                    byte_arr = []
                    for item in arr_data:
                        if item == '':
                            item = 0
                        byte_arr.append(item)
                    arguments.append('[B:' + str(byte_arr))

                    return arguments

    def get_return_variable_name(self, line):
        mro_statement = re.search(self.MOVE_RESULT_OBJECT, line).group()
        return mro_statement[mro_statement.rindex(' ') + 1:]

    def pre_process(self, snippet):
        '''
            预处理 sget指令
        '''
        emu2 = Emulator()
        args = {}

        clz_sigs = set()
        field_desc_prog = re.compile(r'^.*, (.*?->.*)$')
        for line in snippet:
            if 'sget' in line:
                field_desc = field_desc_prog.match(line).groups()[0]
                field = self.smalidir.get_field(field_desc)
                if field:
                    value = field.get_value()
                    if value:
                        args.update({field_desc: value})
                        continue
                clz_sigs.add(field_desc.split('->')[0])

        for clz_sig in clz_sigs:
            mtd = self.smalidir.get_method(clz_sig, '<clinit>()V')
            if mtd:
                body = mtd.get_body()
                tmp = re.split(r'\n\s*', body)
                emu2.call(tmp, thrown=False)
                args.update(emu2.vm.variables)

                for (key, value) in emu2.vm.variables.items():
                    if clz_sig in key:
                        field = self.smalidir.get_field(key)
                        field.set_value(value)

        return args

    @staticmethod
    def get_json_item(cls_name, mtd_name, args):
        item = {'className': cls_name,
                'methodName': mtd_name,
                'arguments': args}
        item['id'] = hashlib.sha256(JSONEncoder().encode(item).encode(
            'utf-8')).hexdigest()
        return item

    def append_json_item(self, json_item, mtd, old_content, rtn_name):
        mid = json_item['id']
        if rtn_name:
            new_content = 'const-string %s, ' % rtn_name + '%s'
        else:
            # const-string v0, "Dexsim"
            # const-string v1, "Decode String"
            # invoke-static {v0, v1}, Landroid/util/Log;->d(
            # Ljava/lang/String;Ljava/lang/String;)I
            new_content = ('const-string v0, "Dexsim"\n'
                           'const-string v1, %s\n'
                           'invoke-static {v0, v1}, Landroid/util/Log;->d'
                           '(Ljava/lang/String;Ljava/lang/String;)I\n')

        if mid not in self.target_contexts:
            self.target_contexts[mid] = [(mtd, old_content, new_content)]
        else:
            self.target_contexts[mid].append((mtd, old_content, new_content))

        if json_item not in self.json_list:
            self.json_list.append(json_item)

    def run(self):
        pass

    def optimize(self):
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

        try:
            print(outputs)
        except UnicodeEncodeError:
            print(str(outputs).encode('utf-8'))

        for key, value in outputs.items():
            if 'success' not in value:
                continue
            if key not in self.target_contexts:
                print('not found', end='')
                continue

            if len(value[1]) == 2:
                continue

            # print(bytearray(value[1], encoding='utf-8'))

            # json_item, mtd, old_content, rtn_name
            for item in self.target_contexts[key]:
                old_body = item[0].body
                old_content = item[1]
                new_content = item[2] % value[1]

                # It's not a string.
                if outputs[key][1] == 'null':
                    continue

                item[0].body = old_body.replace(old_content, new_content)
                item[0].modified = True
                self.make_changes = True

        self.smali_files_update()

    def clear(self):
        self.json_list.clear()
        self.target_contexts.clear()

    def smali_files_update(self):
        '''
            write changes to smali files
        '''
        if self.make_changes:
            for sf in self.smalidir:
                sf.update()
