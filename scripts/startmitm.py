import os
import json
import signal
import sys
from lamda.client import *
from time import sleep

def signal_handler(signum, frame):
    """
    处理系统信号
    
    Args:
        signum: 信号编号
        frame: 当前栈帧
    """
    print(f"Received signal {signum}, cleaning up...")
    cleanup_devices()
    sys.exit(0)

def cleanup_devices():
    """
    清理设备资源
    遍历环境变量中的设备列表，停止代理并显示停止提示
    """
    devices = os.environ.get('DEVICES', '[]')
    device_domains = json.loads(devices)
    
    for domain in device_domains:
        try:
            d = Device(domain, certificate="/user/certificates/" + domain + ".pem")
            d.show_toast("停止代理")
            d.stop_gproxy()
        except Exception as e:
            print(f"Error during cleanup: {e}")

def start_proxy(d):
    """
    为指定设备启动代理服务
    
    Args:
        d: 设备对象
    """
    profile = GproxyProfile()
    profile.type = GproxyType.HTTPS_CONNECT
    profile.drop_udp = True
    profile.host = "127.0.0.1"
    profile.port = 8080
    d.start_gproxy(profile)

def main():
    """
    主函数
    设置信号处理器，初始化设备代理服务，并保持程序运行状态
    """
    # 注册信号处理器
    signal.signal(signal.SIGTERM, signal_handler)  # 进程终止信号
    signal.signal(signal.SIGINT, signal_handler)   # Ctrl+C 信号
    signal.signal(signal.SIGHUP, signal_handler)   # 挂起信号
    signal.signal(signal.SIGQUIT, signal_handler)  # 退出信号

    script_data = os.environ.get('SCRIPT_DATA', '{}')
    data = json.loads(script_data)

    devices = os.environ.get('DEVICES', '[]')
    device_domains = json.loads(devices)
    
    if len(device_domains) == 0:
        print("No devices provided")
        return
    
    try:
        for domain in device_domains:
            d = Device(domain, certificate="/user/certificates/" + domain + ".pem")
            start_proxy(d)
            d.show_toast("开启代理")
            
        while True:
            sleep(1)
    except Exception as e:
        print(e)
        cleanup_devices()

if __name__ == "__main__":
    main()