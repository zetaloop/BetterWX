from _utils import *

title("WeChat 4.1.0.34 Anti-Revoke Patch")
print("\n - Automatic patch application")
print(" - Based on successful analysis")

# 补丁配置
PATCH_CONFIG = {
    "target_file": "C:\\Program Files\\Tencent\\Weixin\\4.1.0.34\\Weixin.dll",
    "patch_offset": 0x0090CF39,
    "original_bytes": bytes.fromhex("0F94C0C3"),
    "patch_bytes": bytes.fromhex("31C090C3"),
    "description": "qy_revoke_msg string comparison function"
}

def verify_environment():
    """验证环境和文件"""
    print(f"\n{BOLD}=== 环境验证 ==={NO_BOLD}")
    
    target_file = PATCH_CONFIG["target_file"]
    
    # 检查文件是否存在
    if not os.path.exists(target_file):
        print(f"{RED}[ERR] 目标文件不存在: {target_file}{RESET}")
        print("请确认微信已正确安装且版本为 4.1.0.34")
        return False
    
    print(f"✓ 找到目标文件: {target_file}")
    
    # 检查文件大小
    file_size = os.path.getsize(target_file)
    expected_size = 153153184  # 从分析中得到的文件大小
    
    if file_size != expected_size:
        print(f"{YELLOW}[WARN] 文件大小不匹配{RESET}")
        print(f"  期望大小: {expected_size:,} 字节")
        print(f"  实际大小: {file_size:,} 字节")
        print("  可能是不同的微信版本，继续执行可能有风险")
        
        confirm = input("是否继续? (输入 'yes' 确认): ")
        if confirm.lower() != 'yes':
            return False
    else:
        print(f"✓ 文件大小匹配: {file_size:,} 字节")
    
    # 检查文件权限
    try:
        with open(target_file, "r+b") as f:
            pass
        print("✓ 文件权限检查通过")
    except PermissionError:
        print(f"{RED}[ERR] 没有修改文件的权限{RESET}")
        print("请以管理员身份运行此脚本")
        return False
    except Exception as e:
        print(f"{RED}[ERR] 文件访问错误: {e}{RESET}")
        return False
    
    return True

def verify_patch_location():
    """验证补丁位置的字节是否正确"""
    print(f"\n{BOLD}=== 补丁位置验证 ==={NO_BOLD}")
    
    target_file = PATCH_CONFIG["target_file"]
    offset = PATCH_CONFIG["patch_offset"]
    expected_bytes = PATCH_CONFIG["original_bytes"]
    
    try:
        with open(target_file, "rb") as f:
            f.seek(offset)
            actual_bytes = f.read(len(expected_bytes))
        
        print(f"补丁位置: 0x{offset:08X}")
        print(f"期望字节: {expected_bytes.hex().upper()}")
        print(f"实际字节: {actual_bytes.hex().upper()}")
        
        if actual_bytes == expected_bytes:
            print(f"{GREEN}✓ 补丁位置字节匹配{RESET}")
            return True
        else:
            print(f"{RED}[ERR] 补丁位置字节不匹配{RESET}")
            print("可能原因:")
            print("1. 微信版本不是 4.1.0.34")
            print("2. 文件已被修改过")
            print("3. 分析结果有误")
            return False
            
    except Exception as e:
        print(f"{RED}[ERR] 读取文件失败: {e}{RESET}")
        return False

def create_backup():
    """创建备份文件"""
    print(f"\n{BOLD}=== 创建备份 ==={NO_BOLD}")
    
    target_file = PATCH_CONFIG["target_file"]
    backup_file = target_file + ".backup"
    
    if os.path.exists(backup_file):
        print(f"{BLUE}[INFO] 备份文件已存在: {backup_file}{RESET}")
        overwrite = input("是否覆盖现有备份? (输入 'yes' 确认): ")
        if overwrite.lower() != 'yes':
            print("使用现有备份文件")
            return True
    
    try:
        import shutil
        shutil.copy2(target_file, backup_file)
        backup_size = os.path.getsize(backup_file)
        print(f"{GREEN}✓ 备份创建成功{RESET}")
        print(f"  备份文件: {backup_file}")
        print(f"  备份大小: {backup_size:,} 字节")
        return True
        
    except Exception as e:
        print(f"{RED}[ERR] 创建备份失败: {e}{RESET}")
        return False

def apply_patch():
    """应用补丁"""
    print(f"\n{BOLD}=== 应用补丁 ==={NO_BOLD}")
    
    target_file = PATCH_CONFIG["target_file"]
    offset = PATCH_CONFIG["patch_offset"]
    patch_bytes = PATCH_CONFIG["patch_bytes"]
    
    print(f"目标: {PATCH_CONFIG['description']}")
    print(f"位置: 0x{offset:08X}")
    print(f"补丁: {patch_bytes.hex().upper()}")
    print()
    
    print(f"{YELLOW}警告: 即将修改微信核心文件{RESET}")
    print(f"此操作将:")
    print(f"• 禁用撤回消息的删除功能")
    print(f"• 实现防撤回效果")
    print(f"• 可能影响微信的其他功能")
    print()
    
    confirm = input("确认应用补丁? (输入 'APPLY' 确认): ")
    if confirm != 'APPLY':
        print("已取消补丁应用")
        return False
    
    try:
        # 应用补丁
        with open(target_file, "r+b") as f:
            f.seek(offset)
            f.write(patch_bytes)
        
        # 验证补丁是否成功应用
        with open(target_file, "rb") as f:
            f.seek(offset)
            written_bytes = f.read(len(patch_bytes))
        
        if written_bytes == patch_bytes:
            print(f"{GREEN}✓ 补丁应用成功!{RESET}")
            return True
        else:
            print(f"{RED}[ERR] 补丁验证失败{RESET}")
            return False
            
    except Exception as e:
        print(f"{RED}[ERR] 应用补丁失败: {e}{RESET}")
        return False

def provide_instructions():
    """提供使用说明"""
    print(f"\n{BOLD}=== 使用说明 ==={NO_BOLD}")
    
    print(f"{GREEN}补丁应用成功!{RESET}")
    print()
    print("下一步操作:")
    print("1. 完全退出微信 (结束所有微信进程)")
    print("2. 重新启动微信")
    print("3. 测试防撤回功能")
    print()
    print("测试方法:")
    print("• 让朋友发送一条消息然后撤回")
    print("• 检查消息是否仍然可见")
    print("• 观察是否有撤回提示")
    print()
    print(f"{YELLOW}注意事项:{RESET}")
    print("• 如果出现问题，使用备份文件恢复:")
    backup_file = PATCH_CONFIG["target_file"] + ".backup"
    print(f"  copy \"{backup_file}\" \"{PATCH_CONFIG['target_file']}\"")
    print("• 微信更新后需要重新应用补丁")
    print("• 此补丁仅适用于 WeChat 4.1.0.34")

def main():
    """主函数"""
    print(f"\n{BOLD}开始 WeChat 4.1.0.34 防撤回补丁...{NO_BOLD}")
    
    # 步骤1: 环境验证
    if not verify_environment():
        print(f"\n{RED}环境验证失败，停止执行{RESET}")
        pause()
        return
    
    # 步骤2: 补丁位置验证
    if not verify_patch_location():
        print(f"\n{RED}补丁位置验证失败，停止执行{RESET}")
        pause()
        return
    
    # 步骤3: 创建备份
    if not create_backup():
        print(f"\n{RED}创建备份失败，停止执行{RESET}")
        pause()
        return
    
    # 步骤4: 应用补丁
    if not apply_patch():
        print(f"\n{RED}补丁应用失败{RESET}")
        pause()
        return
    
    # 步骤5: 提供说明
    provide_instructions()
    
    print(f"\n{GREEN}补丁过程完成!{RESET}")
    pause()

if __name__ == "__main__":
    main()