from mitmproxy.certs import CertStore
from mitmproxy.tools.main import mitmweb as web
from mitmproxy.options import CONF_DIR, CONF_BASENAME, KEY_SIZE
from mitmproxy.version import VERSION
import json
import os
import zipfile
import tempfile

from lamda.client import *
import subprocess

def run_cmd(cmd, env={}):
    """
    执行系统命令并捕获输出
    
    Args:
        cmd (list): 要执行的命令列表
        
    Returns:
        tuple: (bool, str) 执行成功标志和输出内容
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            env=env
        )
        return True, result.stdout
    except subprocess.CalledProcessError as e:
        return False, e.stderr

def copy_cert_with_hash(download_dir):
    """
    复制证书文件并使用其哈希值作为文件名
    
    Args:
        download_dir (str): 下载目录路径
        
    Returns:
        bool: 操作是否成功
    """
    DIR = os.path.expanduser(CONF_DIR)
    CertStore.from_store(DIR, CONF_BASENAME, KEY_SIZE)
    ca = os.path.join(DIR, "mitmproxy-ca-cert.pem")
    result, output = run_cmd(["openssl", "x509", "-subject_hash_old", "-in", ca, "-noout"])
    if not result:
        print(output)
        return False
    hash_value = output.strip()
    target_path = os.path.join(download_dir, f"{hash_value}.0")
    result, output = run_cmd(["cp", ca, target_path])
    if not result:
        print(output)
        return False
    
    return True

def quick_patch_direct(zip_file, output_file=None):
    """
    直接修补ZIP文件，在其中添加证书文件
    
    Args:
        zip_file (str): 输入的ZIP文件路径
        output_file (str, optional): 输出的ZIP文件路径，默认为None
        
    Returns:
        str or None: 成功时返回输出文件路径，失败时返回None
    """
    """Direct version - assume ZIP root directory is HttpCanary_Decypt"""
    
    if not os.path.exists(zip_file):
        print(f"Error: ZIP file does not exist: {zip_file}")
        return None
    
    if output_file is None:
        base, ext = os.path.splitext(zip_file)
        output_file = f"{base}_patched{ext}"
    
    print(f"Patching {zip_file} ...")
    
    with tempfile.TemporaryDirectory() as tmpdir:        
        # 1. Extract
        with zipfile.ZipFile(zip_file, 'r') as zf:
            zf.extractall(tmpdir)
        
        # 2. Assume only one directory after extraction (HttpCanary_Decypt)
        items = os.listdir(tmpdir)
        if len(items) != 1 or not os.path.isdir(os.path.join(tmpdir, items[0])):
            print(f"Error: Expected one directory, but found: {items}")
            return None
        
        work_dir = os.path.join(tmpdir, items[0])
        
        # 3. Add certificate
        cert_dir = os.path.join(work_dir, 'system', 'etc', 'security', 'cacerts')
        os.makedirs(cert_dir, exist_ok=True)
        
        success = copy_cert_with_hash(cert_dir)
        if not success:
            print(f"Failed to copy certificate!")
            return None
        
        # 4. Recompress - ZIP root directory is work_dir contents
        with zipfile.ZipFile(output_file, 'w') as zf:
            for root, dirs, files in os.walk(work_dir):
                for file in files:
                    full_path = os.path.join(root, file)
                    # Key: relative to work_dir
                    arcname = os.path.relpath(full_path, work_dir)
                    zf.write(full_path, arcname)
                    
        return output_file
            

def init_env(d, domain):
    """
    初始化设备环境，包括连接设备、安装debian模块、配置mitmproxy等
    
    Args:
        d (Device): 设备对象
        domain (str): 设备域名
    """
    result, output = run_cmd(['python3', '-u', '/user/code/adb_pubkey.py', 'install', domain], env={"CERTIFICATE": f"/user/certificates/{domain}.pem"})
    if not result:
        print(output)
        return
    result, output = run_cmd(['adb', 'connect', f'{domain}:5555'])
    if not result:
        print(output)
        return
    
    # 检查并安装debian模块
    if not "debian" in str(d.execute_script('ls /data/usr/modules').stdout):
        print(f"{domain} installing debian...")
        result, output = run_cmd(['adb', 'push', '/user/compressed/lamda-mod-debian-arm64-v8a.tar.gz', '/sdcard/'])
        print(output)
        output = d.execute_script('tar -C /data/usr/modules -xzf /sdcard/lamda-mod-debian-arm64-v8a.tar.gz')
        print(output)
    
    # 安装python
    if not d.execute_script("echo 'python3 -V' | debian /bin/bash").stderr == b'':
        print(f"{domain} installing python...")
        d.execute_script("echo 'apt update' | debian /bin/bash")
        d.execute_script("echo 'apt install -y python3 python3-requests' | debian /bin/bash")
        
    # 检查并安装mitmproxy
    if not d.execute_script("echo 'mitmproxy --version' | debian /bin/bash").stderr == b'':
        print(f"{domain} installing mitmproxy...")
        result, output = run_cmd(['adb', 'push', '/user/compressed/mitmproxy-12.2.1-linux-aarch64.tar.gz', '/sdcard/'])
        print(output)
        d.execute_script('tar -C /data/usr/modules/debian/usr/local/bin -xzf /sdcard/mitmproxy-12.2.1-linux-aarch64.tar.gz')
        DIR = os.path.expanduser(CONF_DIR)
        CertStore.from_store(DIR, CONF_BASENAME, KEY_SIZE)
        result, output = run_cmd(['adb', 'push', DIR, '/sdcard'])
        print(output)
        d.execute_script('mv /sdcard/.mitmproxy /data/usr/modules/debian/root')
        dir = quick_patch_direct("/user/compressed/HttpCanary_Decypt.zip")
        if dir == None:
            return
        result, output = run_cmd(['adb', 'push', dir, '/sdcard/Download'])
        print(output)
    
    
    
    # 这里改为执行抓包过滤脚本文件名，后台点击安装环境后重启生效
    filter_script = "filter.py"
    
    # 这里改为请求过滤后跑任务脚本名，后台点安装环境后不需要重启
    task_script = "qd.py"
    
    # 推送脚本并设置mitmdump守护进程
    result, output = run_cmd(['adb', 'push', f'/user/code/{filter_script}', '/sdcard'])
    print(output)
    result, output = run_cmd(['adb', 'push', f'/user/code/{task_script}', '/sdcard'])
    print(output)
    d.execute_script(f'mv /sdcard/{task_script} /data/usr/modules/debian/root')
    d.execute_script(f'mv /sdcard/{filter_script} /data/usr/modules/debian/root')
    d.execute_script(f'(crontab -l 2>/dev/null | grep -v "@reboot.*mitmdump"; echo "@reboot debian /usr/local/bin/mitmdump -q -p 8080 -s /root/{filter_script} > /sdcard/Documents/mitmproxy.log") | crontab -')
    result, output = run_cmd(['adb', 'disconnect'])
    if not result:
        print(output)
        return
    

def main():
    """
    主函数：从环境变量获取设备信息并初始化每个设备的环境
    """
    # 获取传递的数据
    script_data = os.environ.get('SCRIPT_DATA', '{}')
    data = json.loads(script_data)

    # 获取设备列表
    devices = os.environ.get('DEVICES', '[]')
    device_domains = json.loads(devices)
    if len(device_domains) == 0:
        print("No devices provided")
        return
    
    for domain in device_domains:
        d = Device(domain, certificate="/user/certificates/" + domain + ".pem")
        init_env(d, domain)
        
    result, output = run_cmd(['adb', 'disconnect'])
    if not result:
        print(output)
        return
    
    
    
if __name__ == "__main__":
    main()
