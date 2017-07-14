# -*- coding: utf-8 -*-

import argparse
from time import clock
import os
import subprocess
import shutil
import zipfile
import tempfile
import sys

from cigam import Magic
import powerzip

from smafile import SmaliFile

from .dexsim.driver import Driver
from .dexsim.oracle import Oracle

main_path = ''
for path in sys.path:
    if path != '' and path in __file__:
         main_path = path

with open(os.path.join(main_path, "res", 'smali.txt'), 'r', encoding='utf-8') as f:
    lines = f.readlines()


def clean(smali_dir):
    # remove
    for line in lines:
        clz = line.split('#')[0]
        path = smali_dir + os.sep + clz.replace('.', os.sep).strip('\n')
        if os.path.exists(path):
            print('del %s' % path)
            shutil.rmtree(path)


def dexsim(dex_file, smali_dir, include_str):
    driver = Driver()
    driver.install(dex_file)

    oracle = Oracle(smali_dir, driver, include_str)
    oracle.divine()


def baksmali(dex_file, output_dir='out'):
    '''
    dex to smali
    '''
    cmd = 'baksmali d %s -o %s' % (dex_file, output_dir)
    subprocess.call(cmd, shell=True)
    clean(output_dir)

    return output_dir


def smali(smali_dir, output_file='out.dex'):
    '''
    smali to dex
    '''
    cmd = 'smali a %s -o %s' % (smali_dir, output_file)
    subprocess.call(cmd, shell=True)

    return output_file


def main(args):
    include_str = args.i
    print()

    smali_tempdir = tempfile.mkdtemp()

    output_dex = None
    if args.o:
        output_dex = args.o

    if os.path.isdir(args.f):
        if args.f.endswith('\\') or args.f.endswith('/'):
            smali_dir = args.f[:-1]
        else:
            smali_dir = args.f
        dex_file = smali(smali_dir, os.path.basename(smali_dir) + '.dex')
        dexsim_dex(dex_file, smali_dir, include_str, output_dex)
    elif Magic(args.f).get_type() == 'apk':
        apk_path = args.f

        # 反编译所有的classes\d.dex文件
        tempdir = tempfile.mkdtemp()
        smali_tempdir = tempfile.mkdtemp()

        import re
        ptn = re.compile(r'classes\d*.dex')

        import zipfile
        zipFile = zipfile.ZipFile(apk_path)
        for item in zipFile.namelist():
            if ptn.match(item):
                output_path = zipFile.extract(item, tempdir)
                baksmali(output_path, smali_tempdir)
        zipFile.close()

        # 回编译为临时的dex文件
        target_dex = os.path.join(tempdir, 'new.dex')
        smali(smali_tempdir, target_dex)

        dexsim_dex(target_dex, smali_tempdir, include_str, output_dex)
        shutil.rmtree(tempdir)
    else:
        dex_file = os.path.basename(args.f)
        baksmali(dex_file, smali_tempdir)
        dexsim_dex(dex_file, smali_tempdir, include_str, output_dex)



def dexsim_dex(dex_file, smali_tempdir, include_str, output_dex):
        dexsim(dex_file, smali_tempdir, include_str)
        if output_dex:
            smali(smali_tempdir, output_dex)
        else:
            smali(smali_tempdir, os.path.splitext(os.path.basename(dex_file))[0] + '.sim.dex')
        shutil.rmtree(smali_tempdir)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='dexsim', description='')
    parser.add_argument('f', help='Smali Directory / DEX / APK')
    parser.add_argument('-i', help='Only optimize methods and classes matching the pattern, e.g. La/b/c;->decode')
    parser.add_argument('-o', help='output file path')

    args = parser.parse_args()

    start = clock()
    main(args)
    finish = clock()
    print('\n%fs' % (finish - start))
