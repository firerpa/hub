from lamda.client import *
from time import sleep
import os
import json
import random

def delay():
    """
    随机延迟函数
    随机等待2-5秒的时间
    """
    rand = random.randint(2, 5)
    sleep(rand)

def addFriend(domains, friends):
    """
    向指定域的设备上添加微信好友
    
    Args:
        domains (list): 设备域名列表，用于连接不同的设备
        friends (list): 好友信息列表，包含微信ID和验证信息
    
    Returns:
        None: 该函数无返回值，通过打印输出执行结果
    """
    current_index = 0
    current_domain = domains[current_index]
    for friend in friends:
        try:
            # 连接设备并获取微信应用实例
            d = Device(current_domain, certificate=f"/user/certificates/{current_domain}.pem")
            app = d.application("com.tencent.mm")
            app.stop()
            delay()
            
            # 启动微信应用
            d.start_activity(action='android.intent.action.MAIN',component='com.tencent.mm/com.tencent.mm.ui.LauncherUI')
            sleep(10)
            
            # 点击搜索按钮
            elements = d(resourceId="com.tencent.mm:id/h5y")
            elements.get(0).click()
            delay()
            
            # 点击加号图标
            d(resourceId="com.tencent.mm:id/plus_icon").click()
            delay()
            
            # 选择"添加朋友"选项
            elements = d(resourceId="com.tencent.mm:id/h5n")
            elements.get(1).click()
            delay()
            
            # 点击搜索输入框
            d(resourceId="com.tencent.mm:id/mes").click()
            delay()
            
            # 输入好友微信ID
            d.execute_script(f"input text {friend['wx_id']}\n")
            delay()
            
            # 点击搜索按钮
            d(resourceId="com.tencent.mm:id/mem").click()
            sleep(10)
            
            # 检查当前页面是否为联系人详情页
            current_activity = str(d.execute_script('dumpsys window | grep mCurrentFocus').stdout)
            if not "ContactInfoUI" in current_activity:
                app = d.application("com.tencent.mm")
                app.stop()
                continue
            
            # 点击添加好友按钮
            d.click(Point(x=535,y=980))
            delay()
            
            # 检查当前页面是否为发送验证请求页
            current_activity = str(d.execute_script('dumpsys window | grep mCurrentFocus').stdout)
            if not "SayHiWithSnsPermissionUI" in current_activity:
                app = d.application("com.tencent.mm")
                app.stop()
                continue
            
            # 输入验证信息
            d(className="android.widget.EditText").get(0).click()
            delay()
            d.execute_script("input keyevent 123")
            delay()
            for i in range(1, 20):
                d.execute_script("input keyevent 67")
            for i in range(1, 5):
                d(className="android.widget.EditText").get(0).set_text(friend['auth'])
                delay()
            
            # 返回并发送好友请求
            d.press_key(Keys.KEY_BACK)
            delay()
            d(className="android.widget.Button").click()
            sleep(15)
            
            # 关闭应用并延迟
            app = d.application("com.tencent.mm")
            app.stop()
            delay()
        except Exception as e:
            print(f"{current_domain}执行出错: ")
            print(e)
        else:
            print(f"{current_domain}执行成功！")
        
        current_index = (current_index + 1) % len(domains)
        current_domain = domains[current_index]

def main():
    """
    主函数
    从环境变量中读取脚本数据和设备信息，并调用addFriend函数执行添加好友操作
    """
    # 获取传递的数据
    script_data = os.environ.get('SCRIPT_DATA', '{}')
    data = json.loads(script_data)
    
    friends = data['friends']

    # 获取设备列表
    devices = os.environ.get('DEVICES', '[]')
    device_domains = json.loads(devices)
    addFriend(device_domains, friends)

if __name__ == "__main__":
    main()