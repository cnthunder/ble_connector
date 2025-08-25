import os
import re
import sys
import threading
import asyncio
import configparser
from typing import Dict, Optional, List

from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QPushButton, QLineEdit, QLabel, QStatusBar, QMessageBox,
                             QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
                             QTextEdit, QSplitter)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QObject, QProcess
from PyQt5.QtGui import QFont, QColor, QTextCursor

# 导入 ble_serial 的扫描功能
try:
    from ble_serial.scan import main as scanner
except ImportError:
    # 如果无法导入，可能是打包环境的问题，尝试其他导入方式
    scanner = None

# 导入 ble_serial 连接相关的库
import logging
from bleak.exc import BleakError
from ble_serial import platform_uart as UART
from ble_serial.ports.tcp_socket import TCP_Socket
from ble_serial.log.fs_log import FS_log, Direction
from ble_serial.log.console_log import setup_logger
from ble_serial import cli
from argparse import Namespace
from ble_serial import DEFAULT_PORT, DEFAULT_PORT_MSG


class ConnectionSignals(QObject):
    """自定义信号类，用于线程间通信"""
    connection_success = pyqtSignal(str, str)  # 设备名称, MAC地址
    connection_failed = pyqtSignal(str)  # 错误消息
    log_message = pyqtSignal(str)  # 日志消息
    scan_result = pyqtSignal(list)  # 扫描结果
    auto_connect_failed = pyqtSignal(str)  # 自动连接失败消息


class BLEDeviceConnector(QMainWindow):
    def __init__(self):
        super().__init__()
        self.connection_thread = None
        self.connection_loop = None
        self.serial_loop_instance = None  # 保存SerialLoop实例
        self.scan_process = None
        self.config_file = "conf.ini"
        self.devices = []  # 存储扫描到的设备信息
        self.is_restoring = False  # 标记是否正在恢复历史连接
        self.is_auto_connecting = False  # 标记是否正在自动连接
        self.connected_mac = None  # 记录当前连接的MAC地址
        self.connection_signals = ConnectionSignals()
        self.connection_signals.connection_success.connect(self.on_connection_success)
        self.connection_signals.connection_failed.connect(self.on_connection_failed)
        self.connection_signals.log_message.connect(self.on_log_message)
        self.connection_signals.scan_result.connect(self.on_scan_result)
        self.connection_signals.auto_connect_failed.connect(self.on_auto_connect_failed)
        
        # 确保配置文件存在
        self.ensure_config_exists()
        
        self.init_ui()
        
        # 启动后自动尝试连接历史设备
        QTimer.singleShot(1000, self.auto_connect_on_startup)
        
    def auto_connect_on_startup(self):
        """程序启动时自动尝试连接历史设备"""
        device = self.get_device_info()
        if device and device['mac']:
            self.is_auto_connecting = True
            self.statusBar().showMessage("正在尝试自动连接历史设备...")
            self.connection_signals.log_message.emit("正在尝试自动连接历史设备...")
            self.connect_to_device(device['mac'], device['name'])
        else:
            self.statusBar().showMessage("无历史连接设备，请手动扫描并连接")
            self.connection_signals.log_message.emit("无历史连接设备，请手动扫描并连接")
        
    def on_auto_connect_failed(self, error_msg):
        """自动连接失败处理"""
        self.statusBar().showMessage(error_msg)
        self.connection_signals.log_message.emit(error_msg)
        self.is_auto_connecting = False
        
    def ensure_config_exists(self):
        """确保配置文件存在，如果不存在则创建默认配置"""
        if not os.path.exists(self.config_file):
            self.create_default_config()
    
    def create_default_config(self):
        """创建默认配置文件"""
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
            'name': '',
            'addr_type': 'public',
            'service_uuid': '',
            'read_uuid': '',
            'write_uuid': '',
            'mode': 'rw',
            'write_with_response': 'False',
            'port': DEFAULT_PORT
        }
        
        with open(self.config_file, 'w', encoding='utf-8') as f:
            config.write(f)
    
    def load_config(self) -> configparser.ConfigParser:
        """加载配置文件并返回ConfigParser对象"""
        config = configparser.ConfigParser()
        config.read(self.config_file, encoding='utf-8')
        return config
    
    def save_config(self, device: Dict):
        """保存设备配置到文件（只保存最后一次连接）"""
        config = self.load_config()
        
        # 更新设备信息
        if 'DEFAULT' not in config:
            config['DEFAULT'] = {}
        
        config['DEFAULT']['device'] = device['mac']
        config['DEFAULT']['name'] = device['name']
        
        with open(self.config_file, 'w', encoding='utf-8') as f:
            config.write(f)
            
        self.update_history_display()
    
    def get_args_from_config(self) -> Namespace:
        """从配置文件创建参数对象"""
        config = self.load_config()
        args = Namespace()
        
        # 从配置文件中读取所有参数
        args.verbose = int(config.get('DEFAULT', 'verbose', fallback='0'))
        args.timeout = float(config.get('DEFAULT', 'timeout', fallback='3.0'))
        args.adapter = config.get('DEFAULT', 'adapter', fallback='hci0')
        args.mtu = int(config.get('DEFAULT', 'mtu', fallback='20'))
        args.gap_role = config.get('DEFAULT', 'gap_role', fallback='client')
        args.gap_name = config.get('DEFAULT', 'gap_name', fallback='')
        args.device = config.get('DEFAULT', 'device', fallback='')
        args.addr_type = config.get('DEFAULT', 'addr_type', fallback='public')
        args.service_uuid = config.get('DEFAULT', 'service_uuid', fallback='') or None
        args.read_uuid = config.get('DEFAULT', 'read_uuid', fallback='') or None
        args.write_uuid = config.get('DEFAULT', 'write_uuid', fallback='') or None
        args.mode = config.get('DEFAULT', 'mode', fallback='rw')
        args.write_with_response = config.getboolean('DEFAULT', 'write_with_response', fallback=False)
        args.port = config.get('DEFAULT', 'port', fallback=DEFAULT_PORT)
        
        return args
    
    def get_device_info(self) -> Optional[Dict]:
        """获取保存的设备信息"""
        config = self.load_config()
        if 'DEFAULT' in config:
            device = config['DEFAULT'].get('device', '')
            name = config['DEFAULT'].get('name', '')
            if device:
                return {'mac': device, 'name': name}
        return None
    
    def init_ui(self):
        self.setWindowTitle('咖啡烘豆机蓝牙连接Ver1.0（by火柴）')
        # 获取屏幕尺寸和窗口尺寸
        screen_geometry = QApplication.desktop().screenGeometry()
        width, height = 400, 600
        x = (screen_geometry.width() - width) // 2
        y = (screen_geometry.height() - height) // 2
    
        # 设置窗口位置和大小
        self.setGeometry(x, y, width, height)
        
        # 中央部件
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # 主布局
        main_layout = QVBoxLayout(central_widget)
        
        # 第一行按钮
        button_layout1 = QHBoxLayout()
        self.scan_button = QPushButton('扫描')
        self.connect_button = QPushButton('连接')
        self.disconnect_button = QPushButton('断开')
        
        self.scan_button.clicked.connect(self.start_scan)
        self.connect_button.clicked.connect(self.connect_to_selected)
        self.disconnect_button.clicked.connect(self.disconnect_device)
        
        button_layout1.addWidget(self.scan_button)
        button_layout1.addWidget(self.connect_button)
        button_layout1.addWidget(self.disconnect_button)
        
        # 第二行：合并恢复历史连接和历史连接显示
        history_layout = QHBoxLayout()
        self.restore_button = QPushButton('恢复历史连接')
        self.restore_button.clicked.connect(self.restore_last_connection)
        
        self.history_display = QLineEdit()
        self.history_display.setReadOnly(True)
        self.update_history_display()
        
        # 设置宽度比例
        history_layout.addWidget(self.restore_button, 1)  # 与扫描按钮同宽度
        history_layout.addWidget(self.history_display, 2)  # 连接和断开按钮宽度之和
        
        # 设备表格
        display_label = QLabel('设备扫描结果 (单击选择设备):')
        self.device_table = QTableWidget()
        self.device_table.setColumnCount(3)
        self.device_table.setHorizontalHeaderLabels(['设备名称', 'MAC地址', '信号强度'])
        self.device_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.device_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.device_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.device_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        
        # 日志显示框
        log_label = QLabel('后台日志输出:')
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        self.log_display.setMaximumHeight(120)  # 限制高度为4行
        
        # 底部状态栏
        self.statusBar().showMessage('未连接')
        
        # 添加到主布局
        main_layout.addLayout(button_layout1)
        main_layout.addLayout(history_layout)
        main_layout.addWidget(display_label)
        main_layout.addWidget(self.device_table)
        main_layout.addWidget(log_label)
        main_layout.addWidget(self.log_display)
        
    def update_history_display(self):
        """更新历史连接显示"""
        device = self.get_device_info()
        if device:
            self.history_display.setText(f"{device['name']} - {device['mac']}")
        else:
            self.history_display.clear()
    
    def filter_ansi_escape(self, text):
        """过滤ANSI转义序列"""
        # ANSI转义序列正则表达式
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', text)
    
    def on_log_message(self, message: str):
        """处理日志消息"""
        # 过滤ANSI转义序列
        clean_message = self.filter_ansi_escape(message)
        self.log_display.append(clean_message)
        # 自动滚动到底部
        cursor = self.log_display.textCursor()
        cursor.movePosition(QTextCursor.End)
        self.log_display.setTextCursor(cursor)
    
    def on_scan_result(self, devices):
        """处理扫描结果"""
        self.devices = devices
        self.device_table.setRowCount(0)
        
        if not devices:
            self.device_table.setRowCount(1)
            self.device_table.setItem(0, 0, QTableWidgetItem("未找到可用设备，请重试"))
            self.device_table.setItem(0, 1, QTableWidgetItem(""))
            self.device_table.setItem(0, 2, QTableWidgetItem(""))
            self.statusBar().showMessage("扫描完成，未找到任何设备")
            self.connection_signals.log_message.emit("扫描完成，未找到任何设备")
        else:
            for device in devices:
                row = self.device_table.rowCount()
                self.device_table.insertRow(row)
                self.device_table.setItem(row, 0, QTableWidgetItem(device['name']))
                self.device_table.setItem(row, 1, QTableWidgetItem(device['address']))
                self.device_table.setItem(row, 2, QTableWidgetItem(str(device['rssi'])))
            
            self.statusBar().showMessage(f"扫描完成，找到 {len(devices)} 个设备")
            self.connection_signals.log_message.emit(f"扫描完成，找到 {len(devices)} 个设备")
    
    def start_scan(self):
        """开始扫描BLE设备"""
        self.device_table.setRowCount(0)
        self.devices = []
        self.statusBar().showMessage("正在扫描BLE设备...")
        self.connection_signals.log_message.emit("开始扫描BLE设备...")
        
        # 使用线程运行异步扫描
        scan_thread = threading.Thread(target=self.run_scan)
        scan_thread.daemon = True
        scan_thread.start()
    
    def run_scan(self):
        """运行扫描（在单独的线程中）"""
        try:
            # 创建新的事件循环
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            # 运行扫描
            devices = loop.run_until_complete(self.scan_devices())
            
            # 发送扫描结果
            self.connection_signals.scan_result.emit(devices)
            
        except Exception as e:
            error_msg = f"扫描失败: {str(e)}"
            self.statusBar().showMessage(error_msg)
            self.connection_signals.log_message.emit(error_msg)
    
    async def scan_devices(self):
        """使用 ble_serial API 扫描设备"""
        if scanner is None:
            # 如果无法导入 scanner，使用空的设备列表
            self.connection_signals.log_message.emit("警告: 无法导入扫描器模块")
            return []
        
        try:
            # 从配置文件获取扫描参数
            args = self.get_args_from_config()
            
            # 调用 ble_serial 的扫描功能
            devices_dict = await scanner.scan(args.adapter, args.timeout, args.service_uuid)
            
            # 格式化设备信息
            formatted_devices = []
            for mac, (ble_device, adv_data) in devices_dict.items():
                # 从 AdvertisementData 获取 RSSI
                rssi = adv_data.rssi if hasattr(adv_data, 'rssi') else "未知"
                
                # 从 BLEDevice 获取设备名称
                device_name = ble_device.name if hasattr(ble_device, 'name') and ble_device.name else "未知设备"
                
                formatted_devices.append({
                    'name': device_name,
                    'address': mac,
                    'rssi': str(rssi)
                })
            
            return formatted_devices
            
        except Exception as e:
            self.connection_signals.log_message.emit(f"API扫描失败: {str(e)}")
            return []
    
    def connect_to_selected(self):
        """连接到选中的设备"""
        # 获取当前选中的行
        selected_rows = self.device_table.selectionModel().selectedRows()
        
        if not selected_rows:
            self.statusBar().showMessage("请先选择要连接的设备")
            return
        
        # 获取选中行的索引
        row = selected_rows[0].row()
        
        if 0 <= row < len(self.devices):
            device = self.devices[row]
            self.is_restoring = False  # 标记为正常连接，不是恢复连接
            self.is_auto_connecting = False  # 标记为非自动连接
            self.connect_to_device(device['address'], device['name'])
        else:
            self.statusBar().showMessage("无效的设备选择")
    
    def connect_to_device(self, mac: str, name: str = ""):
        """连接到指定的BLE设备"""
        self.statusBar().showMessage(f"正在连接到设备 {name if name else mac}...")
        self.connection_signals.log_message.emit(f"正在连接到设备 {name if name else mac}...")
        QApplication.processEvents()  # 更新UI
        
        # 终止可能存在的现有连接
        self.disconnect_device(quiet=True)  # 静默断开，不显示消息
        
        try:
            # 启动连接线程
            self.connection_thread = threading.Thread(target=self.run_connection, args=(mac, name))
            self.connection_thread.daemon = True
            self.connection_thread.start()
            
            self.connected_mac = mac  # 记录当前连接的MAC地址
            self.connection_signals.log_message.emit(f"启动蓝牙连接: {mac}")
            
            # 设置超时检查
            QTimer.singleShot(10000, self.check_connection_timeout)
            
        except Exception as e:
            error_msg = f"错误: 启动连接时发生错误: {str(e)}"
            self.statusBar().showMessage(error_msg)
            self.connection_signals.log_message.emit(error_msg)
            # 如果是自动连接，发送自动连接失败信号
            if self.is_auto_connecting:
                self.connection_signals.auto_connect_failed.emit(f"自动连接失败: {str(e)}")
    
    def run_connection(self, mac: str, name: str):
        """运行连接（在单独的线程中）"""
        try:
            # 创建新的事件循环
            self.connection_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.connection_loop)
            
            # 设置日志记录器
            setup_logger(0, 'client', '')
            
            # 从配置文件获取参数
            args = self.get_args_from_config()
            # 更新设备地址
            args.device = mac
            
            # 创建并运行串口循环
            from ble_serial.bluetooth.ble_client import BLE_client as BLE
            self.serial_loop_instance = self.SerialLoop(args, BLE, self.connection_signals, name, self)
            self.connection_loop.run_until_complete(self.serial_loop_instance.run())
            
        except asyncio.CancelledError:
            # 这是正常的断开连接操作，不需要记录为错误
            self.connection_signals.log_message.emit("连接已正常断开")
        except Exception as e:
            error_msg = f"连接失败: {str(e)}"
            self.connection_signals.connection_failed.emit(error_msg)
            # 如果是自动连接，发送自动连接失败信号
            if self.is_auto_connecting:
                self.connection_signals.auto_connect_failed.emit(f"自动连接失败: {str(e)}")
    
    def check_connection_timeout(self):
        """检查连接超时"""
        if (self.connection_thread and 
            self.connection_thread.is_alive() and
            not self.statusBar().currentMessage().startswith("已连接到")):
            error_msg = "连接超时，请重试"
            self.connection_signals.connection_failed.emit(error_msg)
            # 如果是自动连接，发送自动连接失败信号
            if self.is_auto_connecting:
                self.connection_signals.auto_connect_failed.emit(f"自动连接失败: {error_msg}")
    
    def on_connection_success(self, name: str, mac: str):
        """连接成功处理"""
        # 只有在正常连接（非恢复连接和非自动连接）时才保存配置
        if not self.is_restoring and not self.is_auto_connecting:
            self.save_config({
                'name': name,
                'mac': mac
            })
        
        if self.is_restoring:
            success_msg = f"已连接到: {name} - {mac} (历史连接)"
            self.statusBar().showMessage(success_msg)
            self.connection_signals.log_message.emit(success_msg)
        elif self.is_auto_connecting:
            success_msg = f"已连接到: {name} - {mac} (自动连接)"
            self.statusBar().showMessage(success_msg)
            self.connection_signals.log_message.emit(success_msg)
            self.is_auto_connecting = False  # 重置自动连接标志
        else:
            success_msg = f"已连接到: {name} - {mac}"
            self.statusBar().showMessage(success_msg)
            self.connection_signals.log_message.emit(success_msg)
    
    def on_connection_failed(self, error_msg: str):
        """连接失败处理"""
        self.statusBar().showMessage(error_msg)
        self.connection_signals.log_message.emit(error_msg)
        self.disconnect_device(quiet=True)
        # 如果是自动连接，发送自动连接失败信号
        if self.is_auto_connecting:
            self.connection_signals.auto_connect_failed.emit(f"自动连接失败: {error_msg}")
            self.is_auto_connecting = False  # 重置自动连接标志
    
    def disconnect_device(self, quiet=False):
        """断开设备连接
        :param quiet: 是否静默断开，不显示消息
        """
        # 停止连接循环
        if self.serial_loop_instance:
            # 设置停止标志
            self.serial_loop_instance.running = False
            
            # 如果事件循环正在运行，取消所有任务
            if self.connection_loop and self.connection_loop.is_running():
                # 获取所有任务并取消
                tasks = asyncio.all_tasks(loop=self.connection_loop)
                for task in tasks:
                    task.cancel()
        
        # 更新UI状态
        if not quiet:
            self.statusBar().showMessage("已断开连接")
            self.connection_signals.log_message.emit("已断开连接")
        
        # 重置连接状态
        self.connected_mac = None
        self.connection_loop = None
        self.connection_thread = None
        self.serial_loop_instance = None
    
    def restore_last_connection(self):
        """恢复最后一次连接"""
        device = self.get_device_info()
        
        if not device:
            self.statusBar().showMessage("无可用历史连接，请重新扫描")
            return
        
        self.is_restoring = True  # 标记为恢复连接，不保存配置
        self.is_auto_connecting = False  # 标记为非自动连接
        self.connect_to_device(device['mac'], device['name'])
    
    def closeEvent(self, event):
        """窗口关闭事件处理"""
        # 断开连接
        self.disconnect_device(quiet=True)
        
        event.accept()
    
    class SerialLoop:
        """自定义串口循环类，用于处理蓝牙连接"""
        def __init__(self, args: Namespace, BLE_class, signals: ConnectionSignals, device_name: str, parent):
            self.args = args
            self.BLE_class = BLE_class
            self.signals = signals
            self.device_name = device_name
            self.parent = parent  # 保存父窗口引用
            self.uart = None
            self.bt = None
            self.log = None
            self.running = False
            self.main_tasks = None
        
        async def run(self):
            """运行连接循环"""
            try:
                self.running = True
                await self._run()
            except asyncio.CancelledError:
                # 这是正常的断开连接操作，不需要记录为错误
                self.signals.log_message.emit("连接已正常断开")
            except KeyboardInterrupt:
                self.signals.log_message.emit("连接被用户中断")
            except Exception as e:
                error_msg = f"连接错误: {str(e)}"
                self.signals.log_message.emit(error_msg)
                self.signals.connection_failed.emit(error_msg)
        
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
                
                # 连接设备
                await self.bt.connect(args.device, args.addr_type, args.service_uuid, args.timeout)
                await self.bt.setup_chars(args.write_uuid, args.read_uuid, args.mode, args.write_with_response)

                # 连接成功，发送信号
                self.signals.connection_success.emit(self.device_name, args.device)
                self.signals.log_message.emit('********************')
                self.signals.log_message.emit('蓝牙虚拟串口成功连接')
                self.signals.log_message.emit('********************')

                # 运行主循环
                self.main_tasks = [
                    asyncio.create_task(self.bt.send_loop()),
                    asyncio.create_task(self.bt.check_loop()),
                    asyncio.create_task(self.uart.run_loop())
                ]
                
                try:
                    # 等待所有任务完成或取消
                    done, pending = await asyncio.wait(
                        self.main_tasks,
                        return_when=asyncio.FIRST_COMPLETED
                    )
                    
                    # 检查是否有任务异常
                    for task in done:
                        if task.exception():
                            self.signals.log_message.emit(f"任务异常: {task.exception()}")
                            self.running = False
                except asyncio.CancelledError:
                    # 这是正常的断开连接操作，不需要记录为错误
                    self.signals.log_message.emit("连接任务已取消")
                    raise  # 重新抛出异常，让外层处理
                
            except BleakError as e:
                error_msg = '蓝牙连接失败'
                self.signals.log_message.emit(error_msg)
                self.signals.log_message.emit(str(e))
                self.signals.connection_failed.emit(error_msg)
            except Exception as e:
                self.signals.log_message.emit(f"连接异常: {str(e)}")
                self.signals.connection_failed.emit("连接异常")
            finally:
                # 无论是否发生异常，都确保断开连接和清理资源
                await self.cleanup()
        
        async def cleanup(self):
            """清理资源，断开连接"""
            self.signals.log_message.emit('处理连接断开清理工作……')
            
            # 取消所有任务
            if self.main_tasks:
                for task in self.main_tasks:
                    if not task.done():
                        task.cancel()
                # 等待所有任务完成
                try:
                    await asyncio.gather(*self.main_tasks, return_exceptions=True)
                except asyncio.CancelledError:
                    # 这是正常的，任务被取消了
                    pass
            
            # 断开蓝牙连接
            if self.bt:
                try:
                    await self.bt.disconnect()
                    self.signals.log_message.emit('蓝牙连接已断开')
                except Exception as e:
                    self.signals.log_message.emit(f'断开蓝牙连接时出错: {str(e)}')
            
            # 停止UART
            if self.uart:
                try:
                    self.uart.remove()
                    self.signals.log_message.emit('UART服务已停止')
                except Exception as e:
                    self.signals.log_message.emit(f'停止UART时出错: {str(e)}')
            
            # 完成日志记录
            if self.log:
                try:
                    self.log.finish()
                except Exception as e:
                    self.signals.log_message.emit(f'完成日志记录时出错: {str(e)}')
            self.signals.log_message.emit('********************')
            self.signals.log_message.emit('蓝牙虚拟串口成功断开')
            self.signals.log_message.emit('********************')
        
        def excp_handler(self, loop: asyncio.AbstractEventLoop, context):
            """异常处理程序"""
            self.signals.log_message.emit(f"Asyncio异常: {context['exception']}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = BLEDeviceConnector()
    window.show()
    sys.exit(app.exec_())