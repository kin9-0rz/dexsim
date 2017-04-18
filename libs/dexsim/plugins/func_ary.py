# coding:utf-8
import hashlib
from json import JSONEncoder
import re

from libs.dexsim.plugin import Plugin
from libs.dexsim.plugins.tool import Tool

__all__ = ["FuncAry"]

class FuncAry(Plugin):

    name = "FuncAry"
    version = '0.0.1'
    description = 'Ary类型作为Func的参数，func([TYPE)'

    def __init__(self, driver, methods, smali_files):
        Plugin.__init__(self, driver, methods, smali_files)

    def doc(self):
        '''
        name: dexsim_new_bytes_fail.apk
        md5: 399e39ad94d8e7051f8e02c0ceda1f04

        a.E = d.a(new byte[]{104, 116, 116, 112, 58, 47, 47, 115, 49, 46, 100, 101, 101, 112, 99, 117,
                112, 115, 46, 99, 111, 109, 47, 115, 50, 47});

            const/16 v2, 0x1a
            new-array v0, v2, [B
            fill-array-data v0, :array_1e
            invoke-static {v0}, La/a/a/d;->a([B)Ljava/lang/String;
            move-result-object v0
            sput-object v0, La/a/a/a;->E:Ljava/lang/String;

        see Tool.getAryData
        '''
        pass

    def run(self):
        print('run Plugin: %s' % self.name, end=' -> ')

        prog_static = re.compile(Tool.INVOKE_STATIC_NORMAL)
        for mtd in self.methods:
            lines = mtd.body.split('\n')
            for i in range(len(lines)):
                line = lines[i]
                if 'fill-array-data' not in line:
                    continue

                #(eleLength, eleType, arraydata)
                aryInfo = Tool.getAryData(line, mtd.body)

                remain_body = '\n'.join(lines[i:])
                try:
                    #params, clsname, methodname, paramsType
                    funcInfo = prog_static.search(remain_body).groups()
                except:
                    continue

                #('v0', 'La/a/a/d', 'a', '[B')
                #('v0, v1', 'Landroid/provider/Settings$Secure', 'getString', 'Landroid/content/ContentResolver;Ljava/lang/String;')
                if '[' not in funcInfo[-1]:
                    continue

                #cases for one ary, [B, [I, [J, are the same
                try:
                    type = re.search('^\[\w$', funcInfo[-1]).group()
                    self._processOneAry(type, aryInfo, remain_body, mtd)
                    continue
                except:
                    pass

                #other cases TBD

    def _processOneAry(self, type, aryInfo, remain_body, mtd):
        '''
        @:param type like [B  [I
        @:param aryInfo = {'eleLength':eleLength, 'eleType':eleType, 'arraydata':arraydata}
        @:param funcInfo = (params, clsname, methodname, paramsType)
        @:param remain_body  is the method body after the fill-array (include)
        @:param mtd  is the current method

        @:return

        fill-array-data v0, :array_1e
        invoke-static {v0}, La/a/a/d;->a([B)Ljava/lang/String;
        move-result-object v0

        ==> need to call optimizations
        '''
        prog = re.compile(Tool.FILL_ARRAY_DATA + '\s+' + Tool.INVOKE_STATIC_NORMAL + '\s+' + self.MOVE_RESULT_OBJECT)

        '''
         [{'className':'', 'methodName':'', 'arguments':'', 'id':''}]

         {'1a0be4a8ba8c21b0c556e5d76ed271439dcfc8e9bfaf312bd5d6b7655c70e02b':
            [(<libs.dexsim.smali_file.SmaliMethod object at 0x00000000026EB7B8>,
            'fill-array-data v3, :array_82\n\n  invoke-static {v3}, La/a/a/d;->a([B)Ljava/lang/String;\n\n    move-result-object v3', '\n\n    const-string v3, ')]}
        '''
        json_list = []
        target_contexts = {}

        m = prog.search(remain_body)
        block = m.group()
        array_data_name, params, classname, methodname, paramsType, resultname = m.groups()

        args = ['%s:%s'%(type, str(aryInfo['arraydata']))]
        classname = classname.replace('L', '').replace('/', '.')
        test = {'className': classname, 'methodName': methodname, 'arguments': args}
        return_variable_name = resultname

        # [{'className':'', 'methodName':'', 'arguments':'', 'id':''}]
        ID = hashlib.sha256(JSONEncoder().encode(test).encode('utf-8')).hexdigest()
        test['id'] = ID

        target_contexts[ID] = [(mtd, block, '\n\n    const-string %s, ' % return_variable_name)]
        json_list.append(test)

        self.optimizations(json_list, target_contexts)