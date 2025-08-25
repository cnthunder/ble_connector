import os
import configparser
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter, Namespace
from ble_serial import DEFAULT_PORT, DEFAULT_PORT_MSG

def create_default_config():
    """创建包含所有默认值的配置文件"""
    config = configparser.ConfigParser()
    
    # 设置默认值
    config['DEFAULT'] = {
        'verbose': '0',
        'timeout': '5.0',
        'adapter': 'hci0',
        'mtu': '20',
        'gap_role': 'client',
        'gap_name': '',
        'device': '',
        'addr_type': 'public',
        'service_uuid': '',
        'read_uuid': '',
        'write_uuid': '',
        'mode': 'rw',
        'write_with_response': 'False',
        'filename': '',
        'binlog': 'False',
        'port': DEFAULT_PORT,
        'tcp_host': '127.0.0.1',
        'tcp_port': ''
    }
    
    with open('conf.ini', 'w') as configfile:
        config.write(configfile)
    
    print("已创建默认配置文件: conf.ini")
    return config

def read_config():
    """读取配置文件并返回配置对象"""
    config = configparser.ConfigParser()
    
    # 如果配置文件不存在，则创建默认配置
    if not os.path.exists('conf.ini'):
        config = create_default_config()
    else:
        config.read('conf.ini')
    
    return config

def config_to_args(config):
    """将配置转换为Namespace对象（模拟argparse返回值）"""
    args = Namespace()
    
    # 从配置中读取所有值
    args.verbose = int(config['DEFAULT'].get('verbose', '0'))
    args.timeout = float(config['DEFAULT'].get('timeout', '5.0'))
    args.adapter = config['DEFAULT'].get('adapter', 'hci0')
    args.mtu = int(config['DEFAULT'].get('mtu', '20'))
    args.gap_role = config['DEFAULT'].get('gap_role', 'client')
    args.gap_name = config['DEFAULT'].get('gap_name', '') or None
    args.device = config['DEFAULT'].get('device', '') or None
    args.addr_type = config['DEFAULT'].get('addr_type', 'public')
    args.service_uuid = config['DEFAULT'].get('service_uuid', '') or None
    args.read_uuid = config['DEFAULT'].get('read_uuid', '') or None
    args.write_uuid = config['DEFAULT'].get('write_uuid', '') or None
    args.mode = config['DEFAULT'].get('mode', 'rw')
    args.write_with_response = config['DEFAULT'].getboolean('write_with_response', False)
    args.filename = config['DEFAULT'].get('filename', '') or None
    args.binlog = config['DEFAULT'].getboolean('binlog', False)
    args.port = config['DEFAULT'].get('port', DEFAULT_PORT)
    args.tcp_host = config['DEFAULT'].get('tcp_host', '127.0.0.1')
    tcp_port = config['DEFAULT'].get('tcp_port', '')
    args.tcp_port = int(tcp_port) if tcp_port.isdigit() else None
    
    return args



def parse_args() -> Namespace:
    """替代原来的parse_args函数，从INI文件读取配置"""
    # 读取配置文件
    config = read_config()
    
    # 将配置转换为Namespace对象
    args = config_to_args(config)
    
    return args

# 示例使用
if __name__ == "__main__":
    args = parse_args()
    print("从配置文件读取的参数:")
    for arg in vars(args):
        print(f"{arg}: {getattr(args, arg)}")