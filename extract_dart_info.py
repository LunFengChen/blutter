import io
import os
import re
import requests
import sys
import zipfile
import zlib
from struct import unpack

from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_E_MACHINE 
from elftools.elf.sections import SymbolTableSection

from loguru import logger

# TODO: support both ELF and Mach-O file
def extract_snapshot_hash_flags(libapp_file):
    with open(libapp_file, 'rb') as f:
        elf = ELFFile(f)
        # find "_kDartVmSnapshotData" symbol
        
        # 1. 优先用 .dynsym 查找
        dynsym = elf.get_section_by_name('.dynsym')
        if dynsym:
            try:
                sym_list = dynsym.get_symbol_by_name('_kDartVmSnapshotData')
                if sym_list:
                    sym = sym_list[0]
                    assert sym['st_size'] > 128
                    f.seek(sym['st_value']+20)
                    snapshot_hash = f.read(32).decode()
                    data = f.read(256) # should be enough
                    flags = data[:data.index(b'\0')].decode().strip().split(' ')
                    logger.info("Found snapshot hash and flags via .dynsym")
                    return snapshot_hash, flags
            except Exception as e:
                logger.warning(f"Failed to extract via .dynsym: {e}")
                
        # 2. 如果没有 .dynsym 或找不到符号，尝试在 .rodata 里用特征匹配
        rodata = elf.get_section_by_name('.rodata')
        if rodata:
            data = rodata.data()
            # 假设 snapshot hash 是32字节ASCII，后面跟着flags字符串
            m = re.search(rb'([a-f0-9]{32}) ([\w\- ]+)\x00', data)
            if m:
                snapshot_hash = m.group(1).decode()
                flags = m.group(2).decode().strip().split(' ')
                logger.info("Found snapshot hash and flags via .rodata pattern")
                return snapshot_hash, flags
            else:
                logger.warning("Cannot find snapshot hash and flags pattern in .rodata")

        # 3. 兜底：全文件搜索
        f.seek(0)
        all_data = f.read()
        m = re.search(rb'([a-f0-9]{32}) ([\w\- ]+)\x00', all_data)
        if m:
            snapshot_hash = m.group(1).decode()
            flags = m.group(2).decode().strip().split(' ')
            logger.info("Found snapshot hash and flags via full file scan")
            return snapshot_hash, flags

        logger.error("Failed to extract snapshot hash and flags from %s by all methods.", libapp_file)
        return "", []# 2. fallback to .symtab        

def extract_libflutter_info(libflutter_file):
    with open(libflutter_file, 'rb') as f:
        elf = ELFFile(f)
        if elf.header.e_machine == 'EM_AARCH64': # 183
            arch = 'arm64'
        elif elf.header.e_machine == 'EM_IA_64': # 50
            arch = 'x64'
        else:
            assert False, f"Unsupport architecture: {elf.header.e_machine}"

        section = elf.get_section_by_name('.rodata')
        data = section.data()
        
        sha_hashes = re.findall(b'\x00([a-f\\d]{40})(?=\x00)', data)
        #logger.debug(sha_hashes)
        # all possible engine ids
        engine_ids = [ h.decode() for h in sha_hashes ]
        assert len(engine_ids) == 2, f'found hashes {", ".join(engine_ids)}'
        
        # beta/dev version of flutter might not use stable dart version (we can get dart version from sdk with found engine_id)
        # support only stable
        epos = data.find(b' (stable) (')
        if epos == -1:
            dart_version = None
        else:
            pos = data.rfind(b'\x00', 0, epos) + 1
            dart_version = data[pos:epos].decode()
        
    return engine_ids, dart_version, arch, 'android'

def get_dart_sdk_url_size(engine_ids):
    #url = f'https://storage.googleapis.com/dart-archive/channels/stable/release/3.0.3/sdk/dartsdk-windows-x64-release.zip'
    for engine_id in engine_ids:
        url = f'https://storage.googleapis.com/flutter_infra_release/flutter/{engine_id}/dart-sdk-windows-x64.zip'
        resp = requests.head(url)
        if resp.status_code == 200:
           sdk_size = int(resp.headers['Content-Length'])
           return engine_id, url, sdk_size
    
    return None, None, None

def get_dart_commit(url):
    # in downloaded zip
    # * dart-sdk/revision - the dart commit id of https://github.com/dart-lang/sdk/
    # * dart-sdk/version  - the dart version
    # revision and version zip file records should be in first 4096 bytes
    # using stream in case a server does not support range
    commit_id = None
    dart_version = None
    fp = None
    with requests.get(url, headers={"Range": "bytes=0-4096"}, stream=True) as r:
        if r.status_code // 10 == 20:
            x = next(r.iter_content(chunk_size=4096))
            fp = io.BytesIO(x)
    
    if fp is not None:
        while fp.tell() < 4096-30 and (commit_id is None or dart_version is None):
            #sig, ver, flags, compression, filetime, filedate, crc, compressSize, uncompressSize, filenameLen, extraLen = unpack(fp, '<IHHHHHIIIHH')
            _, _, _, compMethod, _, _, _, compressSize, _, filenameLen, extraLen = unpack('<IHHHHHIIIHH', fp.read(30))
            filename = fp.read(filenameLen)
            #logger.debug(filename)
            if extraLen > 0:
                fp.seek(extraLen, io.SEEK_CUR)
            data = fp.read(compressSize)
            
            # expect compression method to be zipfile.ZIP_DEFLATED
            assert compMethod == zipfile.ZIP_DEFLATED, 'Unexpected compression method'
            if filename == b'dart-sdk/revision':
                commit_id = zlib.decompress(data, wbits=-zlib.MAX_WBITS).decode().strip()
            elif filename == b'dart-sdk/version':
                dart_version = zlib.decompress(data, wbits=-zlib.MAX_WBITS).decode().strip()
    
    # TODO: if no revision and version in first 4096 bytes, get the file location from the first zip dir entries at the end of file (less than 256KB)
    return commit_id, dart_version

def extract_dart_info(libapp_file: str, libflutter_file: str):
    snapshot_hash, flags = extract_snapshot_hash_flags(libapp_file)
    logger.debug('snapshot hash', snapshot_hash)
    logger.debug(flags)

    engine_ids, dart_version, arch, os_name = extract_libflutter_info(libflutter_file)
    # logger.debug('possible engine ids', engine_ids)
    # logger.debug('dart version', dart_version)

    if dart_version is None:
        engine_id, sdk_url, sdk_size = get_dart_sdk_url_size(engine_ids)
        # logger.debug(engine_id)
        # logger.debug(sdk_url)
        # logger.debug(sdk_size)

        commit_id, dart_version = get_dart_commit(sdk_url)
        # logger.debug(commit_id)
        # logger.debug(dart_version)
        #assert dart_version == dart_version_sdk
    
    # TODO: os (android or ios) and architecture (arm64 or x64)
    return dart_version, snapshot_hash, flags, arch, os_name


if __name__ == "__main__":
    libdir = sys.argv[1]
    libapp_file = os.path.join(libdir, 'libapp.so')
    libflutter_file = os.path.join(libdir, 'libflutter.so')
    logger.success(f"libapp_filepath: {libapp_file}, libflutter_filepath: {libflutter_file}")
    logger.debug(extract_dart_info(libapp_file, libflutter_file))
