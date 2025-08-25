import logging
import asyncio
from bleak.exc import BleakError
from ble_serial import platform_uart as UART
from ble_serial.ports.tcp_socket import TCP_Socket
from ble_serial.log.fs_log import FS_log, Direction
from ble_serial.log.console_log import setup_logger
from ble_serial import cli
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
        'port': DEFAULT_PORT
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
    # args.filename = config['DEFAULT'].get('filename', '') or None
    # args.binlog = config['DEFAULT'].getboolean('binlog', False)
    args.port = config['DEFAULT'].get('port', DEFAULT_PORT)
    # args.tcp_host = config['DEFAULT'].get('tcp_host', '127.0.0.1')
    # tcp_port = config['DEFAULT'].get('tcp_port', '')
    # args.tcp_port = int(tcp_port) if tcp_port.isdigit() else None
    
    return args



def parse_args() -> Namespace:
    """替代原来的parse_args函数，从INI文件读取配置"""
    # 读取配置文件
    config = read_config()
    
    # 将配置转换为Namespace对象
    args = config_to_args(config)
    
    return args

class serial_loop():
    def __init__(self, args: cli.Namespace):
        self.args = args
        from ble_serial.bluetooth.ble_client import BLE_client as BLE
        self.BLE_class = BLE

    def start(self):
        try:
            logging.debug(f'Running: {self.args}')
            asyncio.run(self._run())

        # KeyboardInterrupt causes bluetooth to disconnect, but still a exception would be printed here
        except KeyboardInterrupt as e:
            logging.debug('Exit due to KeyboardInterrupt')

    async def _run(self):
        args = self.args
        loop = asyncio.get_event_loop()
        loop.set_exception_handler(self.excp_handler)
        try:
            self.uart = UART(args.port, loop, args.mtu)
            self.bt = self.BLE_class(args.adapter, args.gap_name)
            self.bt.set_receiver(self.uart.queue_write)
            self.uart.set_receiver(self.bt.queue_send)
            self.uart.start()
            
            await self.bt.connect(args.device, args.addr_type, args.service_uuid, args.timeout)
            await self.bt.setup_chars(args.write_uuid, args.read_uuid, args.mode, args.write_with_response)


            logging.info('Running main loop!')
            main_tasks = {
                asyncio.create_task(self.bt.send_loop()),
                asyncio.create_task(self.bt.check_loop()),
                asyncio.create_task(self.uart.run_loop())
            }
            done, pending = await asyncio.wait(main_tasks, return_when=asyncio.FIRST_COMPLETED)
            logging.debug(f'Completed Tasks: {[(t._coro, t.result()) for t in done]}')
            logging.debug(f'Pending Tasks: {[t._coro for t in pending]}')

        except BleakError as e:
            logging.error(f'Bluetooth connection failed')
            logging.exception(e)
        ### KeyboardInterrupts are now received on asyncio.run()
        # except KeyboardInterrupt:
        #     logging.info('Keyboard interrupt received')
        except Exception as e:
            logging.exception(e)
        finally:
            logging.warning('Shutdown initiated')
            if hasattr(self, 'uart'):
                self.uart.remove()
            if hasattr(self, 'bt'):
                await self.bt.disconnect()
            if hasattr(self, 'log'):
                self.log.finish()
            logging.info('Shutdown complete.')


    def excp_handler(self, loop: asyncio.AbstractEventLoop, context):
        # Handles exception from other tasks (inside bleak disconnect, etc)
        # loop.default_exception_handler(context)
        logging.debug(f'Asyncio execption handler called {context["exception"]}')
        logging.exception(context["exception"])

        self.uart.stop_loop()
        self.bt.stop_loop()

def launch():
    args = parse_args()
    print("从配置文件读取的参数:")
    for arg in vars(args):
        print(f"{arg}: {getattr(args, arg)}")
    setup_logger(args.verbose, args.gap_role, args.gap_name)
    serial_loop(args).start()

if __name__ == '__main__':
    launch()