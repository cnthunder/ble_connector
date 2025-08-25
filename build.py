import os
import sys
import shutil
import subprocess
from pathlib import Path

def main():
    # 检查是否在虚拟环境中
    if not hasattr(sys, 'real_prefix') and not (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
        print("请先在 .venv 虚拟环境中运行此脚本")
        return
    
    # 获取项目根目录
    project_dir = Path(__file__).parent.absolute()
    
    # PyInstaller 配置
    app_name = "BLEConnector"
    script_path = project_dir / "ble_connector.py"
    dist_path = project_dir / "dist"
    build_path = project_dir / "build"
    spec_path = project_dir / f"{app_name}.spec"
    
    # 清理之前的构建
    if dist_path.exists():
        shutil.rmtree(dist_path)
    if build_path.exists():
        shutil.rmtree(build_path)
    if spec_path.exists():
        spec_path.unlink()
    
    # 构建 PyInstaller 命令
    pyinstaller_cmd = [
        "pyinstaller",
        "--name", app_name,
        "--distpath", str(dist_path),
        "--workpath", str(build_path),
        "--specpath", str(project_dir),
        "--windowed",  # 如果是 GUI 应用程序
        "--clean",
        "--noconfirm",
        # 隐藏导入（根据需要添加）
        "--hidden-import", "PyQt5.QtCore",
        "--hidden-import", "PyQt5.QtGui",
        "--hidden-import", "PyQt5.QtWidgets",
        "--hidden-import", "ble-serial",
        str(script_path)
    ]
    
    # 移除空字符串
    pyinstaller_cmd = [arg for arg in pyinstaller_cmd if arg]
    
    # 运行 PyInstaller
    print("正在打包应用程序...")
    result = subprocess.run(pyinstaller_cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        print("打包失败:")
        print(result.stderr)
        return
    
    print("打包成功!")
    
    # 复制虚拟环境中的必要 DLL 文件（如果需要）
    copy_dll_files(project_dir, dist_path / app_name)
    
    
    print(f"应用程序已创建在: {dist_path / app_name}")

def copy_dll_files(project_dir, app_dir):
    """复制必要的 DLL 文件"""
    # 这里可以根据需要添加特定的 DLL 文件
    dll_files_to_copy = [
        # 例如: project_dir / ".venv" / "Lib" / "site-packages" / "some_library" / "some_dll.dll"
    ]
    
    for dll_path in dll_files_to_copy:
        if dll_path.exists():
            shutil.copy2(dll_path, app_dir)
            print(f"已复制: {dll_path.name}")


if __name__ == "__main__":
    main()