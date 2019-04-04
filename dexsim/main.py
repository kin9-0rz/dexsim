import argparse
import os
import re
import shutil
import subprocess
import tempfile
import time
import zipfile

from cigam import Magic
from dexsim import DEBUG_MODE
from dexsim.driver import Driver
from dexsim.oracle import Oracle

main_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
JAVA = 'java'

with open(os.path.join(main_path, 'datas', 'filters.txt')) as f:
    lines = f.read().splitlines()


def clean(smali_dir):
    for line in lines:
        clz = line.split('#')[0]
        xpath = smali_dir + os.sep + clz.replace('.', os.sep).strip('\n')
        if os.path.exists(xpath):
            shutil.rmtree(xpath)


def dexsim(apk_file, smali_dir, includes):
    """推送到手机/模拟器，动态解密

    Args:
        apk_file (TYPE): Description
        smali_dir (TYPE): Description
        includes (TYPE): Description
    """
    driver = Driver()
    driver.push_to_dss(apk_file)

    oracle = Oracle(smali_dir, driver, includes)
    oracle.divine()


def baksmali(dex_file, output_dir='out'):
    '''
    dex to smali
    '''
    baksmali_path = os.path.join(main_path, 'smali', 'baksmali.jar')
    cmd = '{} -jar {} d {} -o {}'.format(JAVA,
                                         baksmali_path, dex_file, output_dir)
    subprocess.call(cmd, shell=True)
    return output_dir


def smali(smali_dir, output_file='out.dex'):
    '''
    smali to dex
    '''
    smali_path = os.path.join(main_path, 'smali', 'smali.jar')
    cmd = '{} -jar {} a {} -o {}'.format(JAVA, smali_path, smali_dir, output_file)
    subprocess.call(cmd, shell=True)
    return output_file


def dexsim_apk(apk_file, smali_dir, includes, output_dex):
    """解密apk

    Args:
        apk_file (str): apk文件
        smali_dir (str): smali 目录
        includes (list): 过滤字符串
        output_dex (str): 反编译后的文件
    """
    dexsim(apk_file, smali_dir, includes)
    if output_dex:
        smali(smali_dir, output_dex)
    else:
        smali(smali_dir,
              os.path.splitext(os.path.basename(apk_file))[0] + '.sim.dex')

    if not DEBUG_MODE:
        shutil.rmtree(smali_dir)


def main(args):
    global DEBUG_MODE
    DEBUG_MODE = args.debug
    includes = args.includes

    output_dex = None
    if args.o:
        output_dex = args.o

    if args.s:
        if os.path.isdir(args.s):
            dexsim_apk(args.f, args.s, includes, output_dex)
        return

    smali_dir = None
    if DEBUG_MODE:
        smali_dir = os.path.join(os.path.abspath(os.curdir), 'zzz')
    else:
        smali_dir = tempfile.mkdtemp()

    dex_file = None
    if Magic(args.f).get_type() == 'apk':
        apk_path = args.f

        if DEBUG_MODE:
            tempdir = os.path.join(os.path.abspath(os.curdir), 'tmp_dir')
            if not os.path.exists(tempdir):
                os.mkdir(tempdir)
        else:
            tempdir = tempfile.mkdtemp()

        ptn = re.compile(r'classes\d*.dex')

        zipFile = zipfile.ZipFile(apk_path)
        for item in zipFile.namelist():
            if ptn.match(item):
                output_path = zipFile.extract(item, tempdir)
                baksmali(output_path, smali_dir)
        zipFile.close()

        dex_file = os.path.join(tempdir, 'new.dex')

        smali(smali_dir, dex_file)
        dexsim_apk(args.f, smali_dir, includes, output_dex)
        if not DEBUG_MODE:
            shutil.rmtree(tempdir)

    else:
        print("Please give A apk.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='dexsim', description='')
    parser.add_argument('f', help='APK 文件')
    parser.add_argument('-i', '--includes', nargs='*',
                        help='仅解密包含的类，如abc, a.b.c')
    parser.add_argument('-o', help='output file path')
    parser.add_argument('-d', '--debug', action='store_true', help='开启调试模式')
    parser.add_argument('-s', required=False, help='指定smali目录')
    # TODO parser.add_argument('-b', action='store_true', help='开启STEP_BY_STEP插件')

    args = parser.parse_args()

    start = time.time()
    main(args)
    finish = time.time()
    print('\n%fs' % (finish - start))
