import json
import os
import re
import subprocess
import sys
import threading
import time
import psutil
from typing import Dict, Optional, List

from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QPushButton, QLineEdit, QLabel, QStatusBar, QMessageBox,
                             QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
                             QTextEdit, QSplitter)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QObject, QProcess
from PyQt5.QtGui import QFont, QColor, QTextCursor


class ConnectionSignals(QObject):
    """自定义信号类，用于线程间通信"""
    connection_success = pyqtSignal(str, str)  # 设备名称, MAC地址
    connection_failed = pyqtSignal(str)  # 错误消息
    log_message = pyqtSignal(str)  # 日志消息


class BLEDeviceConnector(QMainWindow):
    def __init__(self):
        super().__init__()
        self.connection_process = None
        self.scan_process = None
        self.config_file = "conf.json"
        self.devices = []  # 存储扫描到的设备信息
        self.is_restoring = False  # 标记是否正在恢复历史连接
        self.connected_mac = None  # 记录当前连接的MAC地址
        self.connection_signals = ConnectionSignals()
        self.connection_signals.connection_success.connect(self.on_connection_success)
        self.connection_signals.connection_failed.connect(self.on_connection_failed)
        self.connection_signals.log_message.connect(self.on_log_message)
        self.init_ui()
        
    def init_ui(self):
        self.setWindowTitle('烘豆机蓝牙连接（by火柴）')
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
                    # 检查配置是否是有效的设备信息
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
    
    def start_scan(self):
        """开始扫描BLE设备"""
        self.device_table.setRowCount(0)
        self.devices = []
        self.statusBar().showMessage("正在扫描BLE设备...")
        self.connection_signals.log_message.emit("开始扫描BLE设备...")
        
        # 检查ble-scan命令是否可用
        try:
            # 使用subprocess检查命令是否存在
            subprocess.run(['ble-scan', '--help'], capture_output=True, timeout=2)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            self.statusBar().showMessage("错误: 未找到ble-scan命令，请确保已正确安装ble-serial")
            self.connection_signals.log_message.emit("错误: 未找到ble-scan命令")
            return
        
        # 使用QProcess执行扫描命令，以便实时获取输出
        try:
            # 启动扫描进程
            self.scan_process = QProcess()
            self.scan_process.readyReadStandardOutput.connect(self.handle_scan_output)
            self.scan_process.readyReadStandardError.connect(self.handle_scan_error)
            self.scan_process.finished.connect(self.scan_finished)
            
            self.scan_process.start('ble-scan')
            self.connection_signals.log_message.emit("启动ble-scan命令")
            
        except Exception as e:
            error_msg = f"错误: 启动扫描失败: {str(e)}"
            self.statusBar().showMessage(error_msg)
            self.connection_signals.log_message.emit(error_msg)
    
    def handle_scan_output(self):
        """处理扫描输出"""
        if self.scan_process:
            output = self.scan_process.readAllStandardOutput().data().decode('utf-8', errors='ignore')
            if output:
                # 过滤ANSI转义序列并记录日志
                clean_output = self.filter_ansi_escape(output)
                self.connection_signals.log_message.emit(f"扫描输出: {clean_output.strip()}")
                self.parse_scan_output(output)
    
    def handle_scan_error(self):
        """处理扫描错误"""
        if self.scan_process:
            error = self.scan_process.readAllStandardError().data().decode('utf-8', errors='ignore')
            if error:
                # 过滤ANSI转义序列并记录日志
                clean_error = self.filter_ansi_escape(error)
                self.connection_signals.log_message.emit(f"扫描错误: {clean_error.strip()}")
    
    def parse_scan_output(self, output: str):
        """解析扫描输出"""
        # 解析扫描结果 - 使用更全面的正则表达式提取信息
        patterns = [
            r'([0-9A-Fa-f:]{17})\s+\(rssi=(-?\d+)\):\s*(.+)',  # 标准格式
            r'([0-9A-Fa-f:]{17})\s+\(RSSI=(-?\d+)\):\s*(.+)',  # RSSI大写
            r'([0-9A-Fa-f:]{17})\s+.*?RSSI:\s*(-?\d+).*?Name:\s*(.+)',  # 其他格式
            r'Device\s+([0-9A-Fa-f:]{17}).*?RSSI:\s*(-?\d+).*?Name:\s*(.+)'  # 设备格式
        ]
        
        lines = output.split('\n')
        for line in lines:
            for pattern in patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    # 根据不同的模式提取信息
                    if pattern == patterns[0] or pattern == patterns[1]:
                        mac = match.group(1)
                        rssi = match.group(2)
                        name = match.group(3).strip()
                    elif pattern == patterns[2]:
                        mac = match.group(1)
                        rssi = match.group(2)
                        name = match.group(3).strip()
                    elif pattern == patterns[3]:
                        mac = match.group(1)
                        rssi = match.group(2)
                        name = match.group(3).strip()
                    
                    if name == "None" or not name:
                        name = "未知设备"
                    
                    # 检查是否已存在该设备
                    device_exists = False
                    for device in self.devices:
                        if device['mac'] == mac:
                            device_exists = True
                            # 更新信号强度
                            device['rssi'] = rssi
                            break
                    
                    if not device_exists:
                        # 存储设备信息
                        device_info = {
                            'name': name,
                            'mac': mac,
                            'rssi': rssi
                        }
                        self.devices.append(device_info)
                        
                        # 添加到表格
                        row = self.device_table.rowCount()
                        self.device_table.insertRow(row)
                        self.device_table.setItem(row, 0, QTableWidgetItem(name))
                        self.device_table.setItem(row, 1, QTableWidgetItem(mac))
                        self.device_table.setItem(row, 2, QTableWidgetItem(rssi))
                    
                    # 找到匹配后跳出循环
                    break
    
    def scan_finished(self, exit_code, exit_status):
        """扫描完成处理"""
        if exit_code == 0:
            if self.device_table.rowCount() == 0:
                self.device_table.setRowCount(1)
                self.device_table.setItem(0, 0, QTableWidgetItem("未找到可用设备，请重试"))
                self.device_table.setItem(0, 1, QTableWidgetItem(""))
                self.device_table.setItem(0, 2, QTableWidgetItem(""))
                self.statusBar().showMessage("扫描完成，未找到任何设备")
                self.connection_signals.log_message.emit("扫描完成，未找到任何设备")
            else:
                self.statusBar().showMessage(f"扫描完成，找到 {len(self.devices)} 个设备")
                self.connection_signals.log_message.emit(f"扫描完成，找到 {len(self.devices)} 个设备")
        else:
            error_msg = f"扫描失败，退出码: {exit_code}"
            self.statusBar().showMessage(error_msg)
            self.connection_signals.log_message.emit(error_msg)
    
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
            self.connect_to_device(device['mac'], device['name'])
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
            # 检查ble-serial命令是否可用
            subprocess.run(['ble-serial', '--help'], capture_output=True, timeout=2)
            
            # 使用QProcess启动连接进程，以便实时获取输出
            self.connection_process = QProcess()
            self.connection_process.readyReadStandardOutput.connect(self.handle_connection_output)
            self.connection_process.readyReadStandardError.connect(self.handle_connection_error)
            self.connection_process.finished.connect(self.connection_finished)
            
            self.connection_process.start('ble-serial', ['-d', mac])
            self.connected_mac = mac  # 记录当前连接的MAC地址
            self.connection_signals.log_message.emit(f"启动ble-serial -d {mac}")
            
            # 设置超时检查
            QTimer.singleShot(10000, self.check_connection_timeout)
            
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            error_msg = "错误: 未找到ble-serial命令，请确保已正确安装ble-serial"
            self.statusBar().showMessage(error_msg)
            self.connection_signals.log_message.emit(error_msg)
        except Exception as e:
            error_msg = f"错误: 启动连接时发生错误: {str(e)}"
            self.statusBar().showMessage(error_msg)
            self.connection_signals.log_message.emit(error_msg)
    
    def handle_connection_output(self):
        """处理连接输出"""
        if self.connection_process:
            output = self.connection_process.readAllStandardOutput().data().decode('utf-8', errors='ignore')
            if output:
                # 过滤ANSI转义序列并记录日志
                clean_output = self.filter_ansi_escape(output)
                self.connection_signals.log_message.emit(f"连接输出: {clean_output.strip()}")
                
                # 检查是否有成功指示器
                if "main.py: Running main loop!" in clean_output:
                    if self.is_restoring:
                        # 如果是恢复连接，从配置文件中获取设备信息
                        device = self.load_config()
                        if device:
                            self.connection_signals.connection_success.emit(
                                device['name'], device['mac']
                            )
                        else:
                            self.connection_signals.connection_success.emit(
                                "未知设备", self.connection_process.arguments()[-1]
                            )
                    else:
                        # 正常连接，使用传入的设备信息
                        device_name = "未知设备"
                        device_mac = self.connection_process.arguments()[-1]
                        
                        # 尝试从设备列表中获取设备名称
                        for device in self.devices:
                            if device['mac'] == device_mac:
                                device_name = device['name']
                                break
                        
                        self.connection_signals.connection_success.emit(device_name, device_mac)
    
    def handle_connection_error(self):
        """处理连接错误"""
        if self.connection_process:
            error = self.connection_process.readAllStandardError().data().decode('utf-8', errors='ignore')
            if error:
                # 过滤ANSI转义序列并记录日志
                clean_error = self.filter_ansi_escape(error)
                self.connection_signals.log_message.emit(f"连接日志: {clean_error.strip()}")
                
                # 检查是否有成功指示器
                if "main.py: Running main loop!" in clean_error:
                    if self.is_restoring:
                        # 如果是恢复连接，从配置文件中获取设备信息
                        device = self.load_config()
                        if device:
                            self.connection_signals.connection_success.emit(
                                device['name'], device['mac']
                            )
                        else:
                            self.connection_signals.connection_success.emit(
                                "未知设备", self.connection_process.arguments()[-1]
                            )
                    else:
                        # 正常连接，使用传入的设备信息
                        device_name = "未知设备"
                        device_mac = self.connection_process.arguments()[-1]
                        
                        # 尝试从设备列表中获取设备名称
                        for device in self.devices:
                            if device['mac'] == device_mac:
                                device_name = device['name']
                                break
                        
                        self.connection_signals.connection_success.emit(device_name, device_mac)
                
                # 检查是否有真正的错误指示器
                elif "error" in clean_error.lower() or "fail" in clean_error.lower():
                    self.connection_signals.connection_failed.emit("连接失败，请重试")
    
    def connection_finished(self, exit_code, exit_status):
        """连接完成处理"""
        if exit_code != 0:
            error_msg = f"连接失败，退出码: {exit_code}"
            self.statusBar().showMessage(error_msg)
            self.connection_signals.log_message.emit(error_msg)
    
    def check_connection_timeout(self):
        """检查连接超时"""
        if (self.connection_process and 
            self.connection_process.state() == QProcess.Running and
            not self.statusBar().currentMessage().startswith("已连接到")):
            self.connection_signals.connection_failed.emit("连接超时，请重试")
    
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
        if self.connection_process and self.connection_process.state() == QProcess.Running:
            self.connection_process.terminate()
    
    def disconnect_device(self, quiet=False):
        """断开设备连接
        :param quiet: 是否静默断开，不显示消息
        """
        # 首先尝试终止QProcess
        if self.connection_process and self.connection_process.state() == QProcess.Running:
            self.connection_process.terminate()
            if not self.connection_process.waitForFinished(2000):  # 等待2秒
                self.connection_process.kill()
                self.connection_process.waitForFinished(1000)
        
        # 额外检查并终止所有ble-serial进程
        self.kill_ble_serial_processes()
        
        # 更新UI状态
        if not quiet:
            self.statusBar().showMessage("已断开连接")
            self.connection_signals.log_message.emit("已断开连接")
        
        # 重置连接状态
        self.connected_mac = None
    
    def kill_ble_serial_processes(self):
        """终止所有ble-serial进程"""
        try:
            # 使用psutil查找并终止所有ble-serial进程
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    # 检查进程命令行是否包含ble-serial
                    if proc.info['cmdline'] and any('ble-serial' in part for part in proc.info['cmdline']):
                        # 终止进程及其子进程
                        parent = psutil.Process(proc.info['pid'])
                        children = parent.children(recursive=True)
                        for child in children:
                            child.terminate()
                        parent.terminate()
                        
                        # 等待进程终止
                        gone, still_alive = psutil.wait_procs(children + [parent], timeout=3)
                        for p in still_alive:
                            p.kill()
                            
                        self.connection_signals.log_message.emit(f"已终止ble-serial进程: {proc.info['pid']}")
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
        except Exception as e:
            self.connection_signals.log_message.emit(f"终止ble-serial进程时出错: {str(e)}")
    
    def restore_last_connection(self):
        """恢复最后一次连接"""
        device = self.load_config()
        
        if not device:
            self.statusBar().showMessage("无可用历史连接，请重新扫描")
            return
        
        self.is_restoring = True  # 标记为恢复连接，不保存配置
        self.connect_to_device(device['mac'], device['name'])
    
    def closeEvent(self, event):
        """窗口关闭事件处理"""
        # 终止所有正在运行的进程
        if self.scan_process and self.scan_process.state() == QProcess.Running:
            self.scan_process.terminate()
        
        # 断开连接
        self.disconnect_device(quiet=True)
        
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = BLEDeviceConnector()
    window.show()
    sys.exit(app.exec_())