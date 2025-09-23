#!/usr/bin/python3
import argparse                   # 解析命令行参数
import glob                       # 文件名模式匹配
import mmap                       # 内存映射文件对象
import os                         # 操作系统接口
import platform                   # 获取操作系统信息
import shutil                     # 文件操作（复制、删除等）
import subprocess                 # 子进程管理
import sys                        # 系统相关参数和函数
import zipfile                    # 处理zip文件
import tempfile                   # 创建临时文件和目录
from loguru import logger         # 日志库

from dartvm_fetch_build import DartLibInfo  # 导入 DartLibInfo 类

CMAKE_CMD = "cmake"               # cmake 命令
NINJA_CMD = "ninja"               # ninja 命令

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))  # 当前脚本目录
BIN_DIR = os.path.join(SCRIPT_DIR, 'bin')                 # bin 目录
PKG_INC_DIR = os.path.join(SCRIPT_DIR, 'packages', 'include')  # include 目录
PKG_LIB_DIR = os.path.join(SCRIPT_DIR, 'packages', 'lib')      # lib 目录
BUILD_DIR = os.path.join(SCRIPT_DIR, 'build')                  # build 目录

# 输入参数封装类
class BlutterInput:
    def __init__(self, libapp_path: str, dart_info: DartLibInfo, outdir: str, rebuild_blutter: bool, create_vs_sln: bool, no_analysis: bool):
        self.libapp_path = libapp_path
        self.dart_info = dart_info
        self.outdir = outdir
        self.rebuild_blutter = rebuild_blutter
        self.create_vs_sln = create_vs_sln

        vers = dart_info.version.split('.', 2)  # 解析 Dart 版本号
        if int(vers[0]) == 2 and int(vers[1]) < 15:
            if not no_analysis:
                logger.debug('Dart version <2.15, force "no-analysis" option')
            no_analysis = True
        self.no_analysis = no_analysis

        # 根据 dart_info 设置名称后缀
        self.name_suffix = ''
        if not dart_info.has_compressed_ptrs:
            self.name_suffix += '_no-compressed-ptrs'
        if no_analysis:
            self.name_suffix += '_no-analysis'
        # 生成 blutter 可执行文件名
        self.blutter_name = f'blutter_{dart_info.lib_name}{self.name_suffix}'
        self.blutter_file = os.path.join(BIN_DIR, self.blutter_name) + ('.exe' if os.name == 'nt' else '')

# 查找 libapp 和 libflutter 文件
def find_lib_files(indir: str):
    app_file = os.path.join(indir, 'libapp.so')
    if not os.path.isfile(app_file):
        app_file = os.path.join(indir, 'App')
        if not os.path.isfile(app_file):
            logger.error(f"Cannot find libapp file in {indir}")
            sys.exit("Cannot find libapp file")
    
    flutter_file = os.path.join(indir, 'libflutter.so')
    if not os.path.isfile(flutter_file):
        flutter_file = os.path.join(indir, 'Flutter')
        if not os.path.isfile(flutter_file):
            logger.error(f"Cannot find libflutter file in {indir}")
            sys.exit("Cannot find libflutter file")
    
    return os.path.abspath(app_file), os.path.abspath(flutter_file)

# 从 APK 文件中提取 libapp.so 和 libflutter.so
def extract_libs_from_apk(apk_file: str, out_dir: str):
    with zipfile.ZipFile(apk_file, "r") as zf:
        try:
            app_info = zf.getinfo('lib/arm64-v8a/libapp.so')
            flutter_info = zf.getinfo('lib/arm64-v8a/libflutter.so')
        except:
            sys.exit("Cannot find libapp.so or libflutter.so in the APK")

        zf.extract(app_info, out_dir)
        zf.extract(flutter_info, out_dir)

        app_file = os.path.join(out_dir, app_info.filename)
        flutter_file = os.path.join(out_dir, flutter_info.filename)
        return app_file, flutter_file

# 查找兼容性宏定义
def find_compat_macro(dart_version: str, no_analysis: bool):
    macros = []
    include_path = os.path.join(PKG_INC_DIR, f'dartvm{dart_version}')
    vm_path = os.path.join(include_path, 'vm')
    with open(os.path.join(vm_path, 'class_id.h'), 'rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access = mmap.ACCESS_READ)
        # 检查 Map/Set 的实现类
        if mm.find(b'V(LinkedHashMap)') != -1:
            macros.append('-DOLD_MAP_SET_NAME=1')
            if mm.find(b'V(ImmutableLinkedHashMap)') == -1:
                macros.append('-DOLD_MAP_NO_IMMUTABLE=1')
        if mm.find(b' kLastInternalOnlyCid ') == -1:
            macros.append('-DNO_LAST_INTERNAL_ONLY_CID=1')
        if mm.find(b'V(TypeRef)') != -1:
            macros.append('-DHAS_TYPE_REF=1')
        if dart_version.startswith('3.') and mm.find(b'V(RecordType)') != -1:
            macros.append('-DHAS_RECORD_TYPE=1')
    
    with open(os.path.join(vm_path, 'class_table.h'), 'rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access = mmap.ACCESS_READ)
        if mm.find(b'class SharedClassTable {') != -1:
            macros.append('-DHAS_SHARED_CLASS_TABLE=1')
    
    with open(os.path.join(vm_path, 'stub_code_list.h'), 'rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access = mmap.ACCESS_READ)
        if mm.find(b'V(InitLateStaticField)') == -1:
            macros.append('-DNO_INIT_LATE_STATIC_FIELD=1')
    
    with open(os.path.join(vm_path, 'object_store.h'), 'rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access = mmap.ACCESS_READ)
        if mm.find(b'build_generic_method_extractor_code)') == -1:
            macros.append('-DNO_METHOD_EXTRACTOR_STUB=1')

    with open(os.path.join(vm_path, 'object.h'), 'rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access = mmap.ACCESS_READ)
        if mm.find(b'AsTruncatedInt64Value()') == -1:
            macros.append('-DUNIFORM_INTEGER_ACCESS=1')
    
    if no_analysis:
        macros.append('-DNO_CODE_ANALYSIS=1')
    
    return macros

# 用 cmake 构建 blutter
def cmake_blutter(input: BlutterInput):
    blutter_dir = os.path.join(SCRIPT_DIR, 'blutter')
    builddir = os.path.join(BUILD_DIR, input.blutter_name)
    
    macros = find_compat_macro(input.dart_info.version, input.no_analysis)
    my_env = None
    if platform.system() == 'Darwin':
        llvm_path = subprocess.run(['brew', '--prefix', 'llvm@16'], capture_output=True, check=True).stdout.decode().strip()
        clang_file = os.path.join(llvm_path, 'bin', 'clang')
        my_env = {**os.environ, 'CC': clang_file, 'CXX': clang_file+'++'}
    # 配置 cmake
    subprocess.run([CMAKE_CMD, '-GNinja', '-B', builddir, f'-DDARTLIB={input.dart_info.lib_name}', f'-DNAME_SUFFIX={input.name_suffix}', '-DCMAKE_BUILD_TYPE=Release', '--log-level=NOTICE'] + macros, cwd=blutter_dir, check=True, env=my_env)

    # 编译并安装 blutter
    subprocess.run([NINJA_CMD], cwd=builddir, check=True)
    subprocess.run([CMAKE_CMD, '--install', '.'], cwd=builddir, check=True)

# 获取 Dart 库信息
def get_dart_lib_info(libapp_path: str, libflutter_path: str) -> DartLibInfo:
    from extract_dart_info import extract_dart_info
    
    
    logger.debug(f'Extract dart info from "{libapp_path}" and "{libflutter_path}"')
    
    dart_version, snapshot_hash, flags, arch, os_name = extract_dart_info(libapp_path, libflutter_path)
    logger.debug(f'Dart version: {dart_version}, Snapshot: {snapshot_hash}, Target: {os_name} {arch}')
    logger.debug('flags: ' + ' '.join(flags))

    has_compressed_ptrs = 'compressed-pointers' in flags
    return DartLibInfo(dart_version, os_name, arch, has_compressed_ptrs, snapshot_hash)

# 构建并运行 blutter
def build_and_run(input: BlutterInput):
    if not os.path.isfile(input.blutter_file) or input.rebuild_blutter:
        # 检查 Dart 静态库是否存在，不存在则下载和构建
        if os.name == 'nt':
            dartlib_file = os.path.join(PKG_LIB_DIR, input.dart_info.lib_name+'.lib')
        else:
            dartlib_file = os.path.join(PKG_LIB_DIR, 'lib'+input.dart_info.lib_name+'.a')
        if not os.path.isfile(dartlib_file):
            from dartvm_fetch_build import fetch_and_build
            fetch_and_build(input.dart_info)
        
        input.rebuild_blutter = True

    # 如果需要生成 Visual Studio 解决方案
    if input.create_vs_sln:
        macros = find_compat_macro(input.dart_info.version, input.no_analysis)
        blutter_dir = os.path.join(SCRIPT_DIR, 'blutter')
        dbg_output_path = os.path.abspath(os.path.join(input.outdir, 'out'))
        dbg_cmd_args = f'-i {input.libapp_path} -o {dbg_output_path}'
        subprocess.run([CMAKE_CMD, '-G', 'Visual Studio 17 2022', '-A', 'x64', '-B', input.outdir, f'-DDARTLIB={input.dart_info.lib_name}', 
                        f'-DNAME_SUFFIX={input.name_suffix}', f'-DDBG_CMD:STRING={dbg_cmd_args}'] + macros + [blutter_dir], check=True)
        dbg_exe_dir = os.path.join(input.outdir, 'Debug')
        os.makedirs(dbg_exe_dir, exist_ok=True)
        for filename in glob.glob(os.path.join(BIN_DIR, '*.dll')):
            shutil.copy(filename, dbg_exe_dir)
    else:
        if input.rebuild_blutter:
            cmake_blutter(input)
            assert os.path.isfile(input.blutter_file), "Build complete but cannot find Blutter binary: " + input.blutter_file

        # 执行 blutter
        subprocess.run([input.blutter_file, '-i', input.libapp_path, '-o', input.outdir], check=True)

# 仅指定 dart 版本时的主入口
def main_no_flutter(libapp_path: str, dart_version: str, outdir: str, rebuild_blutter: bool, create_vs_sln: bool, no_analysis: bool):
    version, os_name, arch = dart_version.split('_')
    dart_info = DartLibInfo(version, os_name, arch)
    input = BlutterInput(libapp_path, dart_info, outdir, rebuild_blutter, create_vs_sln, no_analysis)
    build_and_run(input)
    
# 标准主入口（libapp 和 libflutter 都有）
def main2(libapp_path: str, libflutter_path: str, outdir: str, rebuild_blutter: bool, create_vs_sln: bool, no_analysis: bool):
    logger.debug(f"[*] found libapp and libflutter: {libapp_path}, {libflutter_path}")
    dart_info = get_dart_lib_info(libapp_path, libflutter_path)
    logger.debug(f"dart_info: {dart_info}")
    input = BlutterInput(libapp_path, dart_info, outdir, rebuild_blutter, create_vs_sln, no_analysis)
    logger.debug(f"blutter input: {input.__dict__}")
    build_and_run(input)
    
    
# 顶层主入口
def main(indir: str, outdir: str, rebuild_blutter: bool, create_vs_sln: bool, no_analysis: bool):
    """支持apk文件和目录两种输入
    如果是apk文件, 就用工具提取出libapp和libflutter, 否则就直接在目录中找这两个文件
    """
    # 如果输入路径以 .apk 结尾，说明是一个 APK 文件
    if indir.endswith(".apk"):
        # 创建一个临时目录用于解压 APK 中的 so 文件
        with tempfile.TemporaryDirectory() as tmp_dir:
            # 从 APK 中提取 libapp.so 和 libflutter.so 到临时目录
            libapp_file, libflutter_file = extract_libs_from_apk(indir, tmp_dir)
            # 进入主流程，处理提取出来的 so 文件
            main2(libapp_file, libflutter_file, outdir, rebuild_blutter, create_vs_sln, no_analysis)
    else:
        # 如果不是 APK，直接在目录中查找 libapp 和 libflutter
        libapp_file, libflutter_file = find_lib_files(indir)
        # 进入主流程，处理找到的 so 文件
        main2(libapp_file, libflutter_file, outdir, rebuild_blutter, create_vs_sln, no_analysis)

# 命令行参数解析与程序入口
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='B(l)utter',
        description='Reversing a flutter application tool')
    # TODO: 支持 ipa
    parser.add_argument('indir', help='An apk or a directory that contains both libapp.so and libflutter.so')
    parser.add_argument('outdir', help='An output directory')
    parser.add_argument('--rebuild', action='store_true', default=False, help='Force rebuild the Blutter executable')
    parser.add_argument('--vs-sln', action='store_true', default=False, help='Generate Visual Studio solution at <outdir>')
    parser.add_argument('--no-analysis', action='store_true', default=False, help='Do not build with code analysis')
    # 罕见用法
    parser.add_argument('--dart-version', help='Run without libflutter (indir become libapp.so) by specify dart version such as "3.4.2_android_arm64"')
    args = parser.parse_args()

    if args.dart_version is None:
        logger.debug(f"not give dart_version -> main")
        main(args.indir, args.outdir, args.rebuild, args.vs_sln, args.no_analysis)
    else:
        logger.debug(f"give specific dart_version -> main_no_flutter")
        main_no_flutter(args.indir, args.dart_version, args.outdir, args.rebuild, args.vs_sln, args.no_analysis)