# coding:utf-8
'''
    插件的功能：

    1. 根据正则表达式匹配，需要解密的区域
    2. 将代码区解析为，类、方法、参数
    [{'className':'', 'methodName':'', 'arguments':'', 'id':''}]
    3. 生成json格式，增加区域ID(Hash)

'''

from json import JSONEncoder
import tempfile
import os
import hashlib
import re


class Plugin(object):
    name = 'Plugin'
    description = ''
    version = ''
    enabled = True

    # const/16 v2, 0x1a
    CONST_NUMBER = 'const(?:\/\d+) [vp]\d+, (-?0x[a-f\d]+)\s+'
    # ESCAPE_STRING = '''"(.*?)(?<!\\\\)"'''
    ESCAPE_STRING = '''"(.*?)"'''
    # const-string v3, "encode string"
    CONST_STRING = 'const-string [vp]\d+, ' + ESCAPE_STRING + '.*'
    # move-result-object v0
    MOVE_RESULT_OBJECT = 'move-result-object ([vp]\d+)'
    # new-array v1, v1, [B
    NEW_BYTE_ARRAY = 'new-array [vp]\d+, [vp]\d+, \[B\s+'
    # new-array v1, v1, [B
    NEW_INT_ARRAY = 'new-array [vp]\d+, [vp]\d+, \[I\s+'
    # new-array v1, v1, [B
    NEW_CHAR_ARRAY = 'new-array [vp]\d+, [vp]\d+, \[C\s+'
    # fill-array-data v1, :array_4e
    FILL_ARRAY_DATA = 'fill-array-data [vp]\d+, :array_[\w\d]+\s+'

    ARRAY_DATA_PATTERN = r':array_[\w\d]+\s*.array-data[\w\W\s]+.end array-data'

    # 保存需要解密的类名、方法、参数 [{'className':'', 'methodName':'', 'arguments':'', 'id':''}]
    json_list = []
    # 目标上下文，解密后用于替换
    target_contexts = {}
    # 保存参数:array_的内容？有必要么？ sget可能会重复获取
    data_arraies = {}

    def __init__(self, driver, methods, smali_files):
        self.make_changes = False
        self.driver = driver
        self.methods = methods
        self.smali_files = smali_files

    def get_invoke_pattern(self, args):
        '''
            根据参数，生成对应invoke-static语句的正则表达式(RE)
        '''
        return r'invoke-static[/\s\w]+\{[vp,\d\s\.]+},\s+([^;]+);->([^\(]+\(%s\))Ljava/lang/String;\s*' % args

    def get_class_name(self, line):
        start = line.index('}, L')
        end = line.index(';->')
        return line[start + 4:end].replace('/', '.')

    def get_method_name(self, line):
        end = line.index(';->')
        args_index = line.index('(')
        return line[end + 3:args_index]

    def get_clz_mtd_name(self, line):
        clz_name, mtd_name = re.search('invoke-static.*?{.*?}, (.*?);->(.*?)\(.*?\)Ljava/lang/String;', line).groups()
        clz_name = clz_name[1:].replace('/', '.')
        return (clz_name, mtd_name)

    def get_clz_mtd_rtn_name(self, line):
        '''
            class_name, method_name, return_variable_name
        '''
        clz_name, mtd_name = re.search('invoke-static.*?{.*?}, (.*?);->(.*?)\(.*?\)Ljava/lang/String;', line).groups()
        clz_name = clz_name[1:].replace('/', '.')

        prog = re.compile(self.MOVE_RESULT_OBJECT)
        mro_statement = prog.search(line).group()
        rtn_name = mro_statement[mro_statement.rindex(' ') + 1:]
        return (clz_name, mtd_name, rtn_name)

    def get_array_data(self, contant):
        ptn1 = re.compile(':array_[\w\d]+')
        array_data_name = ptn1.search(line).group()
        pass

    def get_arguments_from_clinit(self, field):
        supt_obj_ptn = '([\w\W]+?)sput-object (v\d+), %s' % re.escape(field)
        sput_obj_prog = re.compile(supt_obj_ptn)

        from smaliemu.emulator import Emulator
        emu = Emulator()

        arr_data_prog = re.compile(self.ARRAY_DATA_PATTERN)


        class_name = field.split('->')[0]
        for sf in self.smali_files:
            if sf.class_name == class_name:
                for mtd in sf.methods:
                    arr = []
                    if mtd.name == '<clinit>':
                        matchs = sput_obj_prog.search(mtd.body).groups()
                        snippet = matchs[0]
                        code_content = matchs[0]

                        return_register_name = matchs[1]
                        arr = re.split(r'\n+', snippet)[:-1]
                        arr.append('return-object %s' % return_register_name)
                        result = arr_data_prog.search(mtd.body)
                        if result:
                            array_data_content = re.split(r'\n+', result.group())
                            arr.extend(array_data_content)

                        try:
                            # TODO 默认异常停止，这种情况可以考虑，全部跑一遍。
                            # 因为有可能参数声明的时候，位置错位，还有可能是寄存器复用。
                            arr_data = emu.call(arr, thrown=True)
                            if len(emu.vm.exceptions) > 0:
                                break

                            arguments = []
                            byte_arr = []
                            for item in arr_data:
                                if item == '':
                                    item = 0
                                byte_arr.append(item)
                            arguments.append('[B:' + str(byte_arr))

                            return arguments
                        except Exception as e:
                            print(e)
                            pass
                        break


    def get_arguments(self, mtd_body, line, proto):
        '''
            获取参数

            sget-object v1, Lcom/a/e/b;->K:[B
            invoke-static {v1}, Lcom/a/n/o;->a([B)Ljava/lang/String;
            move-result-object v1

            在smali初始化的时候，
            .method static constructor <clinit>()V 中，
            如果存在 sput-object 操作，则考虑解密获取这个值，仅仅用于转换？
        '''

        arguments = []
        if proto == '[B':
            ptn1 = re.compile(':array_[\w\d]+')
            array_data_name = ptn1.search(line).group()
            ptn2 = re.compile('\s+' + array_data_name + '\s+.array-data 1\s+' + '[\w\s]+' + '.end array-data')

            result = ptn2.search(mtd_body)
            if result:
                array_data_content = result.group()
                byte_arr = []
                for item in array_data_content.split()[3:-2]:
                    byte_arr.append(eval(item[:-1]))
                arguments.append(proto + ':' + str(byte_arr))
        elif proto == '[I':
            ptn1 = re.compile(':array_[\w\d]+')
            array_data_name = ptn1.search(line).group()
            ptn2 = re.compile('\s+' + array_data_name + '\s+.array-data \d\s+' + '[-\w\s]+' + '.end array-data')

            result = ptn2.search(mtd_body)
            if result:
                array_data_content = result.group()
                byte_arr = []
                for item in array_data_content.split()[3:-2]:
                    byte_arr.append(eval(item))
                arguments.append(proto + ':' + str(byte_arr))
        elif proto == 'java.lang.String':
            ptn = re.compile(r'\"(.*?)\"')
            result = ptn.findall(line)


            import unicodedata
            import binascii
            for item in result:
                args = []
                import codecs
                item = codecs.getdecoder('unicode_escape')(item)[0]

                for i in item.encode("UTF-8"):
                    args.append(i)
                # ([ord(i) for i in item])
                arguments.append("java.lang.String:" + str(args))
            # raise Exception()
        elif proto in ['I', 'II', 'III']:
            prog2 = re.compile(self.CONST_NUMBER)
            arguments = []
            for item in prog2.finditer(line):
                cn = item.group().split(", ")
                arguments.append('I:' + str(eval(cn[1].strip())))
        return arguments

    def get_return_variable_name(self, line):
        p3 = re.compile(self.MOVE_RESULT_OBJECT)
        mro_statement = p3.search(line).group()
        return mro_statement[mro_statement.rindex(' ') + 1:]

    def get_json_item(self, cls_name, mtd_name, args):
        '''
            生成解密目标
        '''
        item = {'className': cls_name, 'methodName': mtd_name, 'arguments': args}
        ID = hashlib.sha256(JSONEncoder().encode(item).encode('utf-8')).hexdigest()
        item['id'] = ID
        return item

    def append_json_item(self, json_item, mtd, old_content, return_variable_name):
        '''
            添加到json_list, target_contexts
        '''
        mid = json_item['id']
        if return_variable_name:
            new_content = '\n\n    const-string %s, ' % return_variable_name + '%s'
        else:
            # const-string v0, "Dexsim"
            # const-string v1, "Decode String"
            # invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

            new_content = (
                    '\n    const-string v0, "Dexsim"\n'
                    '    const-string v1, %s\n'
                    '    invoke-static {v0, v1}, '
                    'Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I\n'
            )

        if mid not in self.target_contexts.keys():
            self.target_contexts[mid] = [(mtd, old_content, new_content)]
        else:
            self.target_contexts[mid].append((mtd, old_content, new_content))

        if json_item not in self.json_list:
            self.json_list.append(json_item)

    def run(self):
        '''
            匹配代码，生成指定格式的文件(包含类名、方法、参数)
        '''
        pass

    def get_types(self, proto):
        return re.findall('\[?L[\w\/]+;|\[?\w', proto)

    def optimize(self):
        '''
            重复的代码，考虑去除
            生成json
            生成驱动解密
            更新内存
            写入文件
        '''
        if not self.json_list or not self.target_contexts:
            return

        jsons = JSONEncoder().encode(self.json_list)

        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as fp:
            fp.write(jsons)
        outputs = self.driver.decode(fp.name)
        os.unlink(fp.name)

        # 替换内存
        # output 存放的是解密后的结果。
        for key in outputs:
            # TODO 替换的时候，仍然需要确认
            if 'success' in outputs[key]:
                if key not in self.target_contexts.keys():
                    print('not found', key)
                    continue
                # json_item, mtd, old_content, rtn_name
                for item in self.target_contexts[key]:
                    old_body = item[0].body
                    old_content = item[1]
                    new_content = item[2] % outputs[key][1]

                    # It's not a string.
                    if 'null' == outputs[key][1]:
                        continue

                    # 这里替换的时候，注意，因为是没有行数，所以，把相同的方法都替换了
                    # ID虽然不一样，但是，替换的内容一模一样
                    item[0].body = old_body.replace(old_content, new_content)
                    item[0].modified = True
                    self.make_changes = True

        self.smali_files_update()

    def optimizations(self, json_list, target_contexts):
        '''
            重复的代码，考虑去除
            生成json
            生成驱动解密
            更新内存
            写入文件
        '''
        if not json_list or not target_contexts:
            return

        jsons = JSONEncoder().encode(json_list)

        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as fp:
            fp.write(jsons)
        outputs = self.driver.decode(fp.name)
        os.unlink(fp.name)

        # 替换内存
        # output 存放的是解密后的结果。
        for key in outputs:
            if 'success' in outputs[key]:
                if key not in target_contexts.keys():
                    print('not found', key)
                    continue
                for item in target_contexts[key]:
                    old_body = item[0].body
                    target_context = item[1]
                    new_context = item[2] + outputs[key][1]

                    # It's not a string.
                    if 'null' == outputs[key][1]:
                        continue
                    item[0].body = old_body.replace(target_context, new_context)
                    item[0].modified = True
                    self.make_changes = True


        self.smali_files_update()

    def smali_files_update(self):
        '''
            write changes to smali files
        '''
        if self.make_changes:
            for smali_file in self.smali_files:
                smali_file.update()
