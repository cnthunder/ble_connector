import json
import os
import re
import sys
import asyncio
import logging
from typing import Dict, Optional, List

from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QPushButton, QLineEdit, QLabel, QStatusBar, QMessageBox,
                             QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
                             QTextEdit)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QObject
from PyQt5.QtGui import QFont, QColor, QTextCursor

# 尝试导入 ble-serial 模块
try:
    from ble_serial.scan import main as scanner
    from ble_serial.bluetooth.ble_client import BLE_client
    HAS_BLE_SERIAL = True
except ImportError:
    HAS_BLE_SERIAL = False
    print("警告: 无法导入 ble-serial 模块，将使用命令行方式")


class ConnectionSignals(QObject):
    """自定义信号类，用于线程间通信"""
    connection_success = pyqtSignal(str, str)  # 设备名称, MAC地址
    connection_failed = pyqtSignal(str)  # 错误消息
    log_message = pyqtSignal(str)  # 日志消息
    scan_results = pyqtSignal(list)  # 扫描结果


class BLEDeviceConnector(QMainWindow):
    def __init__(self):
        super().__init__()
        self.config_file = "conf.json"
        self.devices = []  # 存储扫描到的设备信息
        self.is_restoring = False  # 标记是否正在恢复历史连接
        self.connected_mac = None  # 记录当前连接的MAC地址
        self.ble_client = None  # BLE客户端实例
        self.scan_task = None  # 扫描任务
        self.connect_task = None  # 连接任务
        self.connection_signals = ConnectionSignals()
        self.connection_signals.connection_success.connect(self.on_connection_success)
        self.connection_signals.connection_failed.connect(self.on_connection_failed)
        self.connection_signals.log_message.connect(self.on_log_message)
        self.connection_signals.scan_results.connect(self.on_scan_results)
        self.init_ui()
        
    def init_ui(self):
        self.setWindowTitle('BLE 设备连接器')
        self.setGeometry(100, 100, 800, 800)
        
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
        history_layout.addWidget(self.restore_button, 1)
        history_layout.addWidget(self.history_display, 2)
        
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
        self.log_display.setMaximumHeight(100)
        
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
        device = self.load_config()
        if device:
            self.history_display.setText(f"{device['name']} - {device['mac']}")
        else:
            self.history_display.clear()
    
    def load_config(self) -> Optional[Dict]:
        """加载配置文件，返回单个设备信息或None"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    if isinstance(config, dict) and 'mac' in config:
                        return config
            except (json.JSONDecodeError, FileNotFoundError):
                pass
        return None
    
    def save_config(self, device: Dict):
        """保存设备配置到文件（只保存最后一次连接）"""
        with open(self.config_file, 'w', encoding='utf-8') as f:
            json.dump(device, f, indent=4, ensure_ascii=False)
        self.update_history_display()
    
    def on_log_message(self, message: str):
        """处理日志消息"""
        self.log_display.append(message)
        cursor = self.log_display.textCursor()
        cursor.movePosition(QTextCursor.End)
        self.log_display.setTextCursor(cursor)
    
    def on_scan_results(self, devices):
        """处理扫描结果"""
        self.device_table.setRowCount(0)
        self.devices = []
        
        for device in devices:
            device_info = {
                'name': device.name or "未知设备",
                'mac': device.address,
                'rssi': device.rssi
            }
            self.devices.append(device_info)
            
            row = self.device_table.rowCount()
            self.device_table.insertRow(row)
            self.device_table.setItem(row, 0, QTableWidgetItem(device_info['name']))
            self.device_table.setItem(row, 1, QTableWidgetItem(device_info['mac']))
            self.device_table.setItem(row, 2, QTableWidgetItem(str(device_info['rssi'])))
        
        if not devices:
            self.device_table.setRowCount(1)
            self.device_table.setItem(0, 0, QTableWidgetItem("未找到可用设备，请重试"))
            self.device_table.setItem(0, 1, QTableWidgetItem(""))
            self.device_table.setItem(0, 2, QTableWidgetItem(""))
            self.statusBar().showMessage("扫描完成，未找到任何设备")
        else:
            self.statusBar().showMessage(f"扫描完成，找到 {len(devices)} 个设备")
    
    def start_scan(self):
        """开始扫描BLE设备"""
        if not HAS_BLE_SERIAL:
            self.connection_signals.log_message.emit("错误: 未找到 ble-serial 模块")
            self.statusBar().showMessage("错误: 未找到 ble-serial 模块")
            return
        
        self.statusBar().showMessage("正在扫描BLE设备...")
        self.connection_signals.log_message.emit("开始扫描BLE设备...")
        
        # 使用线程执行异步扫描
        import threading
        self.scan_task = threading.Thread(target=self.run_scan, daemon=True)
        self.scan_task.start()
    
    def run_scan(self):
        """运行扫描任务"""
        try:
            # 创建新的事件循环
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            # 运行扫描
            ADAPTER = "hci0"  # 可能需要根据系统调整
            SCAN_TIME = 10  # 扫描10秒
            SERVICE_UUID = None
            
            devices = loop.run_until_complete(scanner.scan(ADAPTER, SCAN_TIME, SERVICE_UUID))
            
            # 发送扫描结果到主线程
            device_list = list(devices.values())
            self.connection_signals.scan_results.emit(device_list)
            self.connection_signals.log_message.emit(f"扫描完成，找到 {len(device_list)} 个设备")
            
        except Exception as e:
            error_msg = f"扫描失败: {str(e)}"
            self.connection_signals.log_message.emit(error_msg)
            self.connection_signals.connection_failed.emit(error_msg)
    
    def connect_to_selected(self):
        """连接到选中的设备"""
        selected_rows = self.device_table.selectionModel().selectedRows()
        
        if not selected_rows:
            self.statusBar().showMessage("请先选择要连接的设备")
            return
        
        row = selected_rows[0].row()
        
        if 0 <= row < len(self.devices):
            device = self.devices[row]
            self.is_restoring = False
            self.connect_to_device(device['mac'], device['name'])
        else:
            self.statusBar().showMessage("无效的设备选择")
    
    def connect_to_device(self, mac: str, name: str = ""):
        """连接到指定的BLE设备"""
        if not HAS_BLE_SERIAL:
            self.connection_signals.log_message.emit("错误: 未找到 ble-serial 模块")
            self.statusBar().showMessage("错误: 未找到 ble-serial 模块")
            return
        
        self.statusBar().showMessage(f"正在连接到设备 {name if name else mac}...")
        self.connection_signals.log_message.emit(f"正在连接到设备 {name if name else mac}...")
        
        # 断开现有连接
        self.disconnect_device(quiet=True)
        
        # 使用线程执行异步连接
        import threading
        self.connect_task = threading.Thread(target=self.run_connect, args=(mac, name), daemon=True)
        self.connect_task.start()
    
    def run_connect(self, mac: str, name: str):
        """运行连接任务"""
        try:
            # 创建新的事件循环
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            # 创建BLE客户端
            ADAPTER = "hci0"
            SERVICE_UUID = None
            WRITE_UUID = None
            READ_UUID = None
            
            self.ble_client = BLE_client(ADAPTER, 'ID')
            
            # 连接设备
            awaitable = self.ble_client.connect(mac, "public", SERVICE_UUID, 10.0)
            connected = loop.run_until_complete(awaitable)
            
            if connected:
                # 设置特征值
                awaitable = self.ble_client.setup_chars(WRITE_UUID, READ_UUID, "rw", False)
                loop.run_until_complete(awaitable)
                
                # 连接成功
                if self.is_restoring:
                    device = self.load_config()
                    if device:
                        self.connection_signals.connection_success.emit(device['name'], device['mac'])
                    else:
                        self.connection_signals.connection_success.emit("未知设备", mac)
                else:
                    self.connection_signals.connection_success.emit(name, mac)
            else:
                self.connection_signals.connection_failed.emit("连接失败，请重试")
                
        except Exception as e:
            error_msg = f"连接失败: {str(e)}"
            self.connection_signals.log_message.emit(error_msg)
            self.connection_signals.connection_failed.emit(error_msg)
    
    def on_connection_success(self, name: str, mac: str):
        """连接成功处理"""
        if self.is_restoring:
            success_msg = f"已连接到: {name} - {mac} (历史连接)"
            self.statusBar().showMessage(success_msg)
            self.connection_signals.log_message.emit(success_msg)
        else:
            success_msg = f"已连接到: {name} - {mac}"
            self.statusBar().showMessage(success_msg)
            self.connection_signals.log_message.emit(success_msg)
            
            # 保存连接信息
            self.save_config({
                'name': name,
                'mac': mac
            })
    
    def on_connection_failed(self, error_msg: str):
        """连接失败处理"""
        self.statusBar().showMessage(error_msg)
        self.connection_signals.log_message.emit(error_msg)
    
    def disconnect_device(self, quiet=False):
        """断开设备连接"""
        if self.ble_client:
            try:
                # 创建新的事件循环用于断开连接
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                
                awaitable = self.ble_client.disconnect()
                loop.run_until_complete(awaitable)
                
                self.ble_client = None
                
                if not quiet:
                    self.statusBar().showMessage("已断开连接")
                    self.connection_signals.log_message.emit("已断开连接")
                    
            except Exception as e:
                error_msg = f"断开连接失败: {str(e)}"
                self.connection_signals.log_message.emit(error_msg)
        else:
            if not quiet:
                self.statusBar().showMessage("没有活动的连接")
    
    def restore_last_connection(self):
        """恢复最后一次连接"""
        device = self.load_config()
        
        if not device:
            self.statusBar().showMessage("无可用历史连接，请重新扫描")
            return
        
        self.is_restoring = True
        self.connect_to_device(device['mac'], device['name'])
    
    def closeEvent(self, event):
        """窗口关闭事件处理"""
        self.disconnect_device(quiet=True)
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = BLEDeviceConnector()
    window.show()
    sys.exit(app.exec_())