# -*- coding: utf-8 -*-

import argparse
from time import clock
import os
import subprocess
import shutil
import zipfile
import tempfile

from magic import Magic
import powerzip

from .dexsim.smali_file import SmaliFile
from .dexsim.driver import Driver
from .dexsim.oracle import Oracle


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

    if os.path.isdir(args.f):
        if args.f.endswith('\\') or args.f.endswith('/'):
            smali_dir = args.f[:-1]
        else:
            smali_dir = args.f
        dex_file = smali(smali_dir, os.path.basename(smali_dir) + '.dex')
        dexsim(dex_file, smali_dir, include_str)
        smali(smali_dir, os.path.basename(smali_dir) + '.sim.dex')
    elif Magic(args.f).get_type == 'apk':
        apk_path = args.f

        apk_sim_path = os.path.splitext(args.f)[0] + '.sim.apk'

        shutil.copyfile(apk_path, apk_sim_path)

        try:
            pzip = powerzip.PowerZip(apk_path)
        except zipfile.BadZipFile:
            print("It seems the apk is corrupted. Please re-zip this apk, test again.")
            return

        dexnames = []
        for name in pzip.namelist():
            if name.startswith('classes') and name.endswith('.dex'):
                pzip.extract(name)
                dexnames.append(name)

                dex_file = name
                smali_dir = baksmali(dex_file)
                dexsim(dex_file, smali_dir, include_str)
                smali(smali_dir, dex_file)
                shutil.rmtree(smali_dir)
        pzip.close()

        pzip = powerzip.PowerZip(apk_sim_path)
        for name in dexnames:
            pzip.add(name, name)
            os.remove(name)
        pzip.save(apk_sim_path)
        pzip.close()

    else:
        dex_file = os.path.basename(args.f)
        temp_dir = tempfile.TemporaryDirectory()
        smali_dir = baksmali(dex_file, temp_dir.name)
        dexsim(dex_file, smali_dir, include_str)
        smali(smali_dir, os.path.splitext(os.path.basename(dex_file))[0] + '.sim.dex')


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='dexsim', description='dex simple, make dex more readable/simple.')
    parser.add_argument('f', help='smali dir, later will support dex/apk')
    parser.add_argument('-i', help='include string.')

    args = parser.parse_args()

    start = clock()
    main(args)
    finish = clock()
    print('\n%fs' % (finish - start))
