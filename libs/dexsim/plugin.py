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
    # fill-array-data v1, :array_4e
    FILL_ARRAY_DATA = 'fill-array-data [vp]\d+, :array_[\w\d]+\s+'
    #
    INVOKE_STATIC_NORMAL = 'invoke-static.*?{(?P<params>.*?)}, (?P<clsname>.*?);->(?P<mtdname>.*?)\((?P<paramsType>.*?)\)Ljava/lang/String;'

    # 保存需要解密的类名、方法、参数 [{'className':'', 'methodName':'', 'arguments':'', 'id':''}]
    json_list = []
    # 目标上下文，解密后用于替换
    target_contexts = {}


    def get_invoke_pattern(self, args):
        '''
            根据参数，生成对应invoke-static语句的正则表达式(RE)
        '''
        return r'invoke-static[/\s\w]+\{[vp,\d\s\.]+},\s+([^;]+);->([^\(]+\(%s\))Ljava/lang/String;\s+' % args

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

    def get_func_info(self, line):
        '''
        :param line:  contains the invoke-static method

        :return:
        '''
        prog = re.compile(self.INVOKE_STATIC_NORMAL)
        m = prog.search(line)

        ret = {'params':'', 'clsname':'', 'mtdname':'', 'paramsType':''}
        try:
            return(m.groupdict())
        except:
            return(ret)

    def decode_params_type(self, paramsType):
        '''
        decode and return params type from string

        :param paramsType:  like 'I[B[Ljava/lang/String;Ljava/lang/String;'
        :return:        should return ['I', '[B', '[java/lang/String', 'java/lang/String']
        '''
        #deal with obj first
        ret =[item for item in re.split('L|;', paramsType.replace('/', '.')) if item]

        #deal with [, array type
        all_types = []
        ary_flag = False
        for part in ret:
            if ary_flag:
                all_types.append('[' + part)
                ary_flag = False
                continue

            if '[' not in part:
                all_types.append(part)
                continue

            for char in part:
                if '[' == char:
                    ary_flag = True
                    continue

                if ary_flag:
                    char = '[' + char
                    ary_flag = False
                all_types.append(char)

        return(all_types)

    def isValidLine(self, line, param, d_param_type):
        '''
        check whether valid, by compare opcode with paramtype
        e.g.  if paramtype is java.lang.string, then line should be like const-string v0, "xx"  etc.
              if paramtype is I,   then line should be like const  v0, 0xAB

        :param line:    the line to be checked
        :param param:  like v0
        :param d_param_type: like {v0:java.lang.String'}

        :return:
        '''
        type = d_param_type.get(param, '')
        if not type:
            return False

        d_type_keywords = {
            'java.lang.String' : 'const-string',   #what about other keywords
            #'I' : '0x',
            #'B' : '0x',
            #'J' : '0x',
            #other cases will all treate "," as keywords, that is will always valid
        }

        keywords = d_type_keywords.get(type, 'WILL_NEVER_EXISTS')
        if keywords not in line:
            return  False
        return True

    def get_params(self, block, ori_params, paramsType):
        '''
        build a common solution for different params

        :param block: the matched block for your target,
                like
                case1:
                    const-string v3, "encode string"
                    invoke-static {v3}, La/b/c;->decryptData2(Ljava/lang/String;)Ljava/lang/String;

                case2:
                    const-string v0, "4db8c06f8baa2fa97518e2fbc78aed7a"
                    const-string v1, "dcc6ee73b95b7008865a1241a3f9f2d4"
                    const-string v2, "89cf037654ae21bd"
                    invoke-static {v0, v1, v2}, Lnpnojrqk/niwjucst/oifhebjg/uihmjzfs/agntdkrh/xumvnbpc/jqwutfvs/dfkxcwot/hcsplder;->alxrefmv(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

        :param ori_params:    v3 for case1
                           v0, v1, v2 for case2

        :param paramsType:   like Ljava/lang/String; for case1
                                Ljava/lang/String;Ljava/lang/String;Ljava/lang/String; for case2

        :return:
        '''
        try:
            #block had betten contains no move-result
            lines_reverse = re.search('(.*)invoke-static', block, re.DOTALL).group().split('\n')[::-1]
        except:
            return([])

        #construct default {param:value}
        params = []
        for item in ori_params.split(','):
            params.append(item.strip())
        d_param_value = dict((param, '') for param in params)

        #construct {param:type}
        paramsType = self.decode_params_type(paramsType)
        d_param_type = {}
        try:
            d_param_type = dict((params[i], paramsType[i]) for i in range(len(params)))
        except:
            #v4, v5 as J
            return([])

        #construct {param:value}
        for line in lines_reverse:
            line = line.strip()
            if all(d_param_value.values()):
                break
            parts = [item.strip() for item in re.split('\s+|,', line, 2) if item]
            for param, value in d_param_value.items():
                if all(d_param_value.values()):
                    break
                if value:
                    continue

                if param in parts and self.isValidLine(line, param, d_param_type):
                    d_param_value[param] = parts[parts.index(param) + 1][1:-1]

        cnt = len(d_param_value)
        if cnt != len(paramsType):
            return([])

        ret = []
        i = 0
        for param in params:
            if d_param_value[param]:
                ret.append('%s:%s'%(paramsType[i], str(d_param_value[param])))
            else:
                return([])
            i += 1
        return(ret)

    def get_arguments(self, mtd_body, line, proto):
        '''
            获取参数
        '''
        args = []
        if proto == '[B':
            ptn1 = re.compile(':array_[\w\d]+')
            array_data_name = ptn1.search(line).group()

            reg = '\s+' + array_data_name + '\s+.array-data 1\s+' + '((0x[\da-f]{2}t)\s+)+' + '.end array-data'
            ptn2 = re.compile('\s+' + array_data_name + '\s+.array-data 1\s+' + '[\w\s]+' + '.end array-data')

            result = ptn2.search(mtd_body)
            if result:
                array_data_context = result.group()
                byte_arr = []
                for item in array_data_context.split()[3:-2]:
                    byte_arr.append(eval(item[:-1]))
                args.append(proto + ':' + str(byte_arr))
        elif proto == 'java.lang.String':
            const_str = re.findall("\".+", line)[-1]
            arg1 = []
            for item in const_str[1:-1].encode("UTF-8"):
                arg1.append(item)
            args.append("java.lang.String:" + str(arg1))
        elif proto in ['I', 'II', 'III']:
            prog2 = re.compile(self.CONST_NUMBER)
            args = []
            for item in prog2.finditer(line):
                cn = item.group().split(", ")
                args.append('I:' + str(eval(cn[1].strip())))
        return args

    def get_return_variable_name(self, line):
        p3 = re.compile(self.MOVE_RESULT_OBJECT)
        mro_statement = p3.search(line).group()
        return mro_statement[mro_statement.rindex(' ') + 1:]

    def get_json_item(self, cls_name, mtd_name, args):
        '''
            生产解密目标
        '''
        item = {'className': cls_name, 'methodName': mtd_name, 'arguments': args}
        ID = hashlib.sha256(JSONEncoder().encode(item).encode('utf-8')).hexdigest()
        item['id'] = ID
        return item


    def append_json_item(self, json_item, mtd, line, return_variable_name):
        '''
            添加到json_list, target_contexts
        '''
        mid = json_item['id']
        if mid not in self.target_contexts.keys():
            self.target_contexts[mid] = [(mtd, line, '\n\n    const-string %s, ' % return_variable_name)]
        else:
            self.target_contexts[mid].append((mtd, line, '\n\n    const-string %s, ' % return_variable_name))

        if json_item not in self.json_list:
            self.json_list.append(json_item)


    def __init__(self, driver, methods, smali_files):
        self.make_changes = False
        self.driver = driver
        self.methods = methods
        self.smali_files = smali_files

    def run(self):
        '''
            匹配代码，生成指定格式的文件(包含类名、方法、参数)
        '''
        pass

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
            if 'success' in outputs[key]:
                if key not in self.target_contexts.keys():
                    print('not found', key)
                    continue
                for item in self.target_contexts[key]:
                    old_body = item[0].body
                    target_context = item[1]
                    new_context = item[2] + outputs[key][1]

                    # It's not a string.
                    if 'null' == outputs[key][1]:
                        continue
                    print('found sth: ', outputs[key][1])
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

def main():
    obj = Plugin(None, None, None)
    line = '[I[B[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;'
    print(obj.decode_params_type(line))

    lines = '''
    const-string v1, "4db8c06f8baa2fa97518e2fbc78aed7a"
                    const-string v0, "dcc6ee73b95b7008865a1241a3f9f2d4"
                    const-string v2, "89cf037654ae21bd"
                    invoke-static {v0, v1, v2}, Lnpnojrqk/niwjucst/oifhebjg/uihmjzfs/agntdkrh/xumvnbpc/jqwutfvs/dfkxcwot/hcsplder;->alxrefmv(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    '''
    funcInfo = obj.get_func_info('invoke-static {v0, v1, v2}, Lnpnojrqk/niwjucst/oifhebjg/uihmjzfs/agntdkrh/xumvnbpc/jqwutfvs/dfkxcwot/hcsplder;->alxrefmv(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;')
    obj.get_params(lines, funcInfo['params'], funcInfo['paramsType'])

if __name__ == "__main__":
    main()