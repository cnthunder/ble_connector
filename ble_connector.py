# 修正之前默认mtu为20的问题，解决GATT服务找不到；
# 优化换行符处理，确保发送数据格式正确；
# 增加调试窗口，实时监控数据收发；
# 版本号更新为1.1

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
                             QTextEdit, QSplitter, QDialog, QFormLayout, QSpinBox, QCheckBox,
                             QTabWidget, QGroupBox)
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


class DebugWindow(QDialog):
    """调试窗口"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.setWindowTitle("调试窗口 - 数据监控")
        self.setModal(False)
        self.setFixedSize(600, 500)
        
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # 创建标签页
        tab_widget = QTabWidget()
        
        # 数据监控标签页
        data_tab = QWidget()
        data_layout = QVBoxLayout(data_tab)
        
        # 发送数据组
        send_group = QGroupBox("发送数据")
        send_layout = QVBoxLayout(send_group)
        
        # UART发送区域（发送到BLE）
        uart_send_layout = QHBoxLayout()
        uart_send_label = QLabel("UART发送到BLE:")
        self.uart_send_text = QLineEdit()
        self.uart_send_text.setPlaceholderText("输入要通过BLE发送的数据...")
        self.uart_send_button = QPushButton("发送")
        self.uart_send_button.clicked.connect(self.send_uart_to_ble)
        
        uart_send_layout.addWidget(uart_send_label)
        uart_send_layout.addWidget(self.uart_send_text)
        uart_send_layout.addWidget(self.uart_send_button)
        
        # BLE发送区域（发送到UART）
        ble_send_layout = QHBoxLayout()
        ble_send_label = QLabel("BLE发送到UART:")
        self.ble_send_text = QLineEdit()
        self.ble_send_text.setPlaceholderText("输入要通过UART发送的数据...")
        self.ble_send_button = QPushButton("发送")
        self.ble_send_button.clicked.connect(self.send_ble_to_uart)
        
        ble_send_layout.addWidget(ble_send_label)
        ble_send_layout.addWidget(self.ble_send_text)
        ble_send_layout.addWidget(self.ble_send_button)
        
        # 发送数据显示
        self.send_display = QTextEdit()
        self.send_display.setReadOnly(True)
        self.send_display.setMaximumHeight(120)
        
        send_layout.addLayout(uart_send_layout)
        send_layout.addLayout(ble_send_layout)
        send_layout.addWidget(self.send_display)
        
        # 接收数据组
        receive_group = QGroupBox("接收数据")
        receive_layout = QVBoxLayout(receive_group)
        self.receive_display = QTextEdit()
        self.receive_display.setReadOnly(True)
        self.receive_display.setMaximumHeight(150)
        receive_layout.addWidget(self.receive_display)
        
        data_layout.addWidget(send_group)
        data_layout.addWidget(receive_group)
        
        tab_widget.addTab(data_tab, "数据监控")
        
        # 按钮
        button_layout = QHBoxLayout()
        self.clear_button = QPushButton("清空显示")
        self.close_button = QPushButton("关闭")
        
        self.clear_button.clicked.connect(self.clear_display)
        self.close_button.clicked.connect(self.hide)
        
        button_layout.addWidget(self.clear_button)
        button_layout.addWidget(self.close_button)
        
        layout.addWidget(tab_widget)
        layout.addLayout(button_layout)
    
    def send_uart_to_ble(self):
        """UART发送数据到BLE（模拟UART端发送）"""
        data = self.uart_send_text.text().strip()
        if data and self.parent:
            self.parent.send_uart_data(data)
            self.uart_send_text.clear()
    
    def send_ble_to_uart(self):
        """BLE发送数据到UART（模拟BLE端发送）"""
        data = self.ble_send_text.text().strip()
        if data and self.parent:
            self.parent.send_ble_data(data)
            self.ble_send_text.clear()
    
    def add_send_data(self, data_type: str, data: str):
        """添加发送数据到调试窗口"""
        display_text = f"[{data_type}发送] {data.strip()}"
        self.send_display.append(display_text)
        # 自动滚动到底部
        cursor = self.send_display.textCursor()
        cursor.movePosition(QTextCursor.End)
        self.send_display.setTextCursor(cursor)
    
    def add_receive_data(self, data_type: str, data: str):
        """添加接收数据到调试窗口"""
        display_text = f"[发往{data_type}] {data.strip()}"
        self.receive_display.append(display_text)
        # 自动滚动到底部
        cursor = self.receive_display.textCursor()
        cursor.movePosition(QTextCursor.End)
        self.receive_display.setTextCursor(cursor)
    
    def clear_display(self):
        """清空显示"""
        self.send_display.clear()
        self.receive_display.clear()


class SettingsDialog(QDialog):
    """设置对话框"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.setWindowTitle("设置")
        self.setModal(True)
        self.setFixedSize(300, 200)
        
        self.init_ui()
        self.load_settings()
    
    def init_ui(self):
        layout = QFormLayout(self)
        
        # MTU设置
        self.mtu_spinbox = QSpinBox()
        self.mtu_spinbox.setRange(20, 512)  # MTU范围20-512
        self.mtu_spinbox.setValue(128)
        self.mtu_spinbox.setToolTip("设置MTU大小，默认128，范围20-512")
        layout.addRow("MTU大小:", self.mtu_spinbox)
        
        # 自动连接设置
        self.auto_connect_checkbox = QCheckBox()
        self.auto_connect_checkbox.setToolTip("启动时自动尝试连接历史设备")
        layout.addRow("启动时自动连接:", self.auto_connect_checkbox)
        
        # 按钮布局
        button_layout = QHBoxLayout()
        self.ok_button = QPushButton("确定")
        self.cancel_button = QPushButton("取消")
        
        self.ok_button.clicked.connect(self.save_settings)
        self.cancel_button.clicked.connect(self.reject)
        
        button_layout.addWidget(self.ok_button)
        button_layout.addWidget(self.cancel_button)
        
        layout.addRow(button_layout)
    
    def load_settings(self):
        """从配置文件加载设置"""
        config = self.parent.load_config()
        
        # 加载MTU设置
        mtu = config.getint('DEFAULT', 'mtu', fallback=128)
        self.mtu_spinbox.setValue(mtu)
        
        # 加载自动连接设置
        auto_connect = config.getboolean('DEFAULT', 'auto_connect', fallback=True)
        self.auto_connect_checkbox.setChecked(auto_connect)
    
    def save_settings(self):
        """保存设置到配置文件"""
        try:
            config = self.parent.load_config()
            
            # 保存MTU设置
            config.set('DEFAULT', 'mtu', str(self.mtu_spinbox.value()))
            
            # 保存自动连接设置
            config.set('DEFAULT', 'auto_connect', str(self.auto_connect_checkbox.isChecked()))
            
            # 写入配置文件
            with open(self.parent.config_file, 'w', encoding='utf-8') as f:
                config.write(f)
            
            self.accept()
            QMessageBox.information(self, "成功", "设置已保存")
            
        except Exception as e:
            QMessageBox.critical(self, "错误", f"保存设置失败: {str(e)}")


class ConnectionSignals(QObject):
    """自定义信号类，用于线程间通信"""
    connection_success = pyqtSignal(str, str)  # 设备名称, MAC地址
    connection_failed = pyqtSignal(str)  # 错误消息
    log_message = pyqtSignal(str)  # 日志消息
    scan_result = pyqtSignal(list)  # 扫描结果
    auto_connect_failed = pyqtSignal(str)  # 自动连接失败消息
    debug_data = pyqtSignal(str, str, str)  # 数据类型, 数据方向, 数据内容


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
        self.connection_signals.debug_data.connect(self.on_debug_data)
        
        # 调试窗口
        self.debug_window = DebugWindow(self)
        
        # 数据缓冲区
        self.receive_buffer = ""
        self.send_buffer = ""
        
        # 确保配置文件存在
        self.ensure_config_exists()
        
        self.init_ui()
        
        # 检查是否启用自动连接
        if self.is_auto_connect_enabled():
            QTimer.singleShot(1000, self.auto_connect_on_startup)
        else:
            self.statusBar().showMessage("自动连接已禁用，请手动扫描并连接")
            self.connection_signals.log_message.emit("自动连接已禁用，请手动扫描并连接")
        
    def is_auto_connect_enabled(self):
        """检查是否启用自动连接"""
        config = self.load_config()
        return config.getboolean('DEFAULT', 'auto_connect', fallback=True)
        
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
            'mtu': '128',
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
            'port': DEFAULT_PORT,
            'auto_connect': 'True'  # 添加自动连接设置
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
        args.mtu = int(config.get('DEFAULT', 'mtu', fallback='128'))  # 默认改为128
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
        self.setWindowTitle('咖啡烘豆机蓝牙连接Ver1.1（by火柴）')
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
        
        # 第一行按钮 - 改为五个按钮
        button_layout1 = QHBoxLayout()
        self.scan_button = QPushButton('扫描')
        self.connect_button = QPushButton('连接')
        self.disconnect_button = QPushButton('断开')
        self.settings_button = QPushButton('设置')
        self.debug_button = QPushButton('调试窗口')  # 新增调试窗口按钮
        
        self.scan_button.clicked.connect(self.start_scan)
        self.connect_button.clicked.connect(self.connect_to_selected)
        self.disconnect_button.clicked.connect(self.disconnect_device)
        self.settings_button.clicked.connect(self.open_settings)
        self.debug_button.clicked.connect(self.open_debug_window)  # 连接调试窗口按钮
        
        button_layout1.addWidget(self.scan_button)
        button_layout1.addWidget(self.connect_button)
        button_layout1.addWidget(self.disconnect_button)
        button_layout1.addWidget(self.settings_button)
        # button_layout1.addWidget(self.debug_button)
        
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
        history_layout.addWidget(self.debug_button, 1)  # 连接和断开按钮宽度之和
        
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
        self.log_display.setMaximumHeight(120)
        
        # 底部状态栏
        self.statusBar().showMessage('未连接')
        
        # 添加到主布局
        main_layout.addLayout(button_layout1)
        main_layout.addLayout(history_layout)
        main_layout.addWidget(display_label)
        main_layout.addWidget(self.device_table)
        main_layout.addWidget(log_label)
        main_layout.addWidget(self.log_display)
    
    def open_debug_window(self):
        """打开调试窗口"""
        self.debug_window.show()
        self.debug_window.raise_()  # 将窗口置于前台
        self.debug_window.activateWindow()  # 激活窗口
    
    def on_debug_data(self, data_type: str, direction: str, data: str):
        """处理调试数据"""
        if direction == 'send':
            self.debug_window.add_send_data(data_type, data)
        elif direction == 'receive':
            self.debug_window.add_receive_data(data_type, data)
    
    def send_uart_data(self, data: str):
        """处理UART发送到BLE的数据"""
        if not self.serial_loop_instance or not self.serial_loop_instance.uart:
            QMessageBox.warning(self, "警告", "未连接到设备")
            return
        
        if not data:
            return
        
        # 处理数据格式：确保以\r\n结尾
        if data.endswith('\n'):
            if not data.endswith('\r\n'):
                data = data.replace('\n', '\r\n')
        else:
            data += '\r\n'
        
        try:
            # 通过UART发送数据（这会触发BLE发送）
            if self.serial_loop_instance.uart and self.connection_loop:
                # 将字符串转换为bytes
                data_bytes = data.encode('utf-8')
                
                # 在调试窗口显示UART发送的数据
                self.connection_signals.debug_data.emit('UART', 'send', data)
                
                # 使用UART的queue_write方法发送数据（这会通过BLE转发）
                self.serial_loop_instance.uart.queue_write(data_bytes)
                
        except Exception as e:
            QMessageBox.critical(self, "错误", f"UART发送数据失败: {str(e)}")
            self.connection_signals.log_message.emit(f"UART发送数据错误: {str(e)}")
    
    def send_ble_data(self, data: str):
        """处理BLE发送到UART的数据"""
        if not self.serial_loop_instance or not self.serial_loop_instance.bt:
            QMessageBox.warning(self, "警告", "未连接到设备")
            return
        
        if not data:
            return
        
        # 处理数据格式：确保以\r\n结尾
        if data.endswith('\n'):
            if not data.endswith('\r\n'):
                data = data.replace('\n', '\r\n')
        else:
            data += '\r\n'
        
        try:
            # 通过BLE发送数据（这会触发UART发送）
            if self.serial_loop_instance.bt and self.connection_loop:
                # 将字符串转换为bytes
                data_bytes = data.encode('utf-8')
                
                # 在调试窗口显示BLE发送的数据
                self.connection_signals.debug_data.emit('BLE', 'send', data)
                
                # 使用BLE的queue_send方法发送数据（这会通过UART转发）
                if hasattr(self.serial_loop_instance.bt, 'queue_send'):
                    self.serial_loop_instance.bt.queue_send(data_bytes)
                
        except Exception as e:
            QMessageBox.critical(self, "错误", f"BLE发送数据失败: {str(e)}")
            self.connection_signals.log_message.emit(f"BLE发送数据错误: {str(e)}")
    
    def open_settings(self):
        """打开设置对话框"""
        settings_dialog = SettingsDialog(self)
        settings_dialog.exec_()
    
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
        
        # 过滤掉蓝牙数据收发的日志消息
        if any(keyword in clean_message for keyword in ['通过蓝牙发送数据', '蓝牙接收数据', 'UART接收数据']):
            return  # 不显示数据收发日志
        
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
                # 显示信号强度，如果是-999则显示"未知"
                rssi_display = str(device['rssi']) if device['rssi'] != -999 else "未知"
                self.device_table.setItem(row, 2, QTableWidgetItem(rssi_display))
            
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
                rssi = adv_data.rssi if hasattr(adv_data, 'rssi') else -999  # 使用-999表示未知信号强度
                
                # 从 BLEDevice 获取设备名称
                device_name = ble_device.name if hasattr(ble_device, 'name') and ble_device.name else "未知设备"
                
                formatted_devices.append({
                    'name': device_name,
                    'address': mac,
                    'rssi': rssi  # 保持为数字用于排序
                })
            
            # 对设备进行排序
            formatted_devices = self.sort_devices(formatted_devices)
            
            return formatted_devices
            
        except Exception as e:
            self.connection_signals.log_message.emit(f"API扫描失败: {str(e)}")
            return []
    
    def sort_devices(self, devices):
        """对设备进行排序：已知设备按信号强度降序，未知设备放在最后"""
        if not devices:
            return devices
        
        # 分离已知设备和未知设备
        known_devices = [dev for dev in devices if dev['name'] != "未知设备"]
        unknown_devices = [dev for dev in devices if dev['name'] == "未知设备"]
        
        # 对已知设备按信号强度降序排序（信号强度高的在前）
        known_devices.sort(key=lambda x: x['rssi'], reverse=True)
        
        # 对未知设备也按信号强度降序排序
        unknown_devices.sort(key=lambda x: x['rssi'], reverse=True)
        
        # 合并列表：已知设备在前，未知设备在后
        sorted_devices = known_devices + unknown_devices
        
        return sorted_devices
    
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
        # 关闭调试窗口
        if self.debug_window.isVisible():
            self.debug_window.close()
        
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
            
            # 数据缓冲区
            self.receive_buffer = bytearray()
        
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
                # 创建UART和蓝牙客户端实例
                self.uart = UART(args.port, loop, args.mtu)
                self.bt = self.BLE_class(args.adapter, args.gap_name)
                
                # 设置正确的数据流方向：
                # BLE接收数据 -> 通过UART发送（BLE到UART）
                self.bt.set_receiver(self._handle_ble_receive)
                
                # UART接收数据 -> 通过BLE发送（UART到BLE）
                self.uart.set_receiver(self._handle_uart_receive)
                
                self.uart.start()
                
                # 连接设备
                await self.bt.connect(args.device, args.addr_type, args.service_uuid, args.timeout)
                await self.bt.setup_chars(args.write_uuid, args.read_uuid, args.mode, args.write_with_response)

                # 连接成功，发送信号
                self.signals.connection_success.emit(self.device_name, args.device)
                self.signals.log_message.emit('>>>蓝牙虚拟串口成功连接')

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
        
        def _handle_ble_receive(self, data: bytes):
            """处理从BLE接收到的数据（BLE -> UART）"""
            try:
                data_str = data.decode('utf-8', errors='ignore')
                
                # 在调试窗口显示BLE接收的数据（实际是BLE发送到UART）
                self.signals.debug_data.emit('BLE', 'receive', data_str)
                
                # 将数据转发到UART（BLE到UART方向）
                if self.uart:
                    self.uart.queue_write(data)
                    
            except Exception as e:
                self.signals.log_message.emit(f"BLE数据处理错误: {str(e)}")
        
        def _handle_uart_receive(self, data: bytes):
            """处理从UART接收到的数据（UART -> BLE）"""
            try:
                data_str = data.decode('utf-8', errors='ignore')
                
                # 在调试窗口显示UART接收的数据（实际是UART发送到BLE）
                self.signals.debug_data.emit('UART', 'receive', data_str)
                
                # 处理数据格式：确保以\r\n结尾
                if data_str.endswith('\n'):
                    if not data_str.endswith('\r\n'):
                        data_str = data_str.replace('\n', '\r\n')
                else:
                    data_str += '\r\n'
                
                # 重新编码为bytes
                formatted_data = data_str.encode('utf-8')
                
                # 通过BLE发送数据（UART到BLE方向）
                if hasattr(self.bt, 'queue_send'):
                    self.bt.queue_send(formatted_data)
                
            except Exception as e:
                self.signals.log_message.emit(f"UART数据处理错误: {str(e)}")
        
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
            self.signals.log_message.emit('>>>蓝牙虚拟串口成功断开')
        
        def excp_handler(self, loop: asyncio.AbstractEventLoop, context):
            """异常处理程序"""
            self.signals.log_message.emit(f"Asyncio异常: {context['exception']}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = BLEDeviceConnector()
    window.show()
    sys.exit(app.exec_())