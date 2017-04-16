import sys
import hashlib
from json import JSONEncoder
import re

__all__ = ["Tool"]

class Tool:
    name = "Tool"
    version = '0.0.1'
    description = 'encapsulations for those commonly used methods'

    FILL_ARRAY_DATA = 'fill-array-data [vp]\d+, (?P<array_data_name>:array_[\w\d]+)'

    #invoke-static {v0}, La/a/a/d;->a([B)Ljava/lang/String;
    #common filter pattern for invoke-static, used to extract params, clsname, methodname, and paramstype, etc
    #   more detailed filter conditions can be added on the results
    INVOKE_STATIC_NORMAL = 'invoke-static.*?{(?P<params>.*?)}, (?P<clsname>.*?);->(?P<methdname>.*?)\((?P<paramsType>.*?)\)Ljava/lang/String;'

    @staticmethod
    def getAryData(array_data_name, mtdBody):
        '''
            @:param array_data_name looks like ":array_le" or "fill-array-data v0, :array_1e"
                     mtdBody is the method body

            @:return {'eleLength':eleLength, 'eleType':eleType, 'arraydata':arraydata}
                    eleLength will like 1, 4, 8
                    eleType will like B, I, J, D, etc   (or byte, int, long, double, float)
                    ary will be the [ele1, ele2, ..]


            private byte [] bAry = new byte[] {104, 116, 116, };
            private int [] intAry = new int[] {6874, 43, 390};
            private  double [] doubleAry = new double [] {5.0, 4.2, 3.0, 1.1};
            private long [] lAry = new long[] {112, 115, 46, 99, 111, 109, 47, 115};

            .line 7
            const/16 v0, 0x1a
            new-array v0, v0, [B
            fill-array-data v0, :array_26
            iput-object v0, p0, Lcom/example/xx/arytype/AryType;->bAry:[B

            .line 9
            const/4 v0, 0x3
            new-array v0, v0, [I
            fill-array-data v0, :array_38
            iput-object v0, p0, Lcom/example/xx/arytype/AryType;->intAry:[I

            .line 10
            const/4 v0, 0x4
            new-array v0, v0, [D
            fill-array-data v0, :array_42
            iput-object v0, p0, Lcom/example/xx/arytype/AryType;->doubleAry:[D

            .line 11
            const/16 v0, 0x8
            new-array v0, v0, [J
            fill-array-data v0, :array_56
            iput-object v0, p0, Lcom/example/xx/arytype/AryType;->lAry:[J

            .line 7
            :array_26
            .array-data 1           #this is the [B  case, 1 indicate its length
                0x68t               # indicate its type
                0x74t
                ...
            .end array-data

            .line 9
            :array_38
            .array-data 4          #this is the [I case, 4 indicate its length
                0x1ada             # indicate its type
                0x2b
                0x186
            .end array-data

            .line 10
            :array_42
            .array-data 8           #this is the double Ary case, its length and type
                0x4014000000000000L    # 5.0
                0x4010cccccccccccdL    # 4.2
                0x4008000000000000L    # 3.0
                0x3ff199999999999aL    # 1.1
            .end array-data

            .line 11
            :array_56
            .array-data 8           #this is the [J   long type, 8 indicate ites length
                0x70                #
                0x73
            .end array-data
        '''
        array_data_name = ''.join(array_data_name.partition(':')[1:])
        pattern = array_data_name + '\s+.array-data (?P<eleLength>\d+)\s+' + '(?P<lines>.*?)' + '.end array-data'
        prog = re.compile(pattern, re.DOTALL) #make . can match newline
        mObj = prog.search(mtdBody)

        eleLength = mObj.group('eleLength')
        eleType = ''
        arraydata = []

        prog_data = re.compile('(?P<value>0x[0-9a-f]+)(?P<type>\w?)')
        lines = mObj.group('lines')
        for line in lines.split('\n'):
            #0x4010cccccccccccdL    # 4.2
            try:
                data = line.strip().split()[0]
            except:
                continue
            m = prog_data.search(data)
            eleType = m.group('type')
            arraydata.append(eval(m.group('value')))

        return {'eleLength':eleLength, 'eleType':eleType, 'arraydata':arraydata}
