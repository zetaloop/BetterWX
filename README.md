# BetterWX
<img width="400" src="https://github.com/user-attachments/assets/4bdfb590-d913-4543-b54c-347f6b1d14e7" />

微信 PC 4.0 防撤回/多开补丁工具

支持平台：Windows x64<br>
支持版本：**WeChat 4.0.6.26 / 4.1.0.34**

**\>\>\> 试试这个带窗口界面的更方便的工具：[afaa1991/BetterWx-UI](https://github.com/afaa1991/BetterWx-UI)**

## 使用方法
0. 首先你要有比较新的 [Python](https://www.python.org/downloads/)，并且关掉了微信和烦人的安全管家。
1. 把仓库克隆下来。
2. 运行下列补丁代码，填入对应的文件路径（不填=自动查找），保存修改前会自动备份原文件.bak。<br>

   - `revoke.py`：**防撤回**<br>（实验性）防撤回且保留提示。方案来自 [EEEEhex/RevokeHook](https://github.com/EEEEhex/RevokeHook) 项目。<br>撤回提示会显示在对应的消息下方。<br>远程撤回时，撤回提示需要重新进入聊天窗口才会刷新出来。<br>电脑端自己撤回时，消息会变成撤回提示，消息本身需要重进聊天窗口才会再次刷新出来。<br>不拦截自己撤回、拍一拍防撤回正在研究。
   - `revoke_4.1.0.34.py`：**防撤回（WeChat 4.1.0.34）**<br>基于目标字节校验与备份，应用补丁后会回读验证。

   - `coexist.py`：**共存**<br>创建一个编号 0~9 的共存版 Weixinζ.exe（最多十个），隔离其互斥锁、窗口名、设置、登录端口。<br>共存版的所有消息记录和原版共用，可以随意换着登录。

   - `sound_extract.py`：**提取提示音**<br>提取提示音到当前目录，文件名为 `Sound_编号_十六进制大小.wav`。

   - `sound_replace.py`：**修改提示音**<br>替换提示音，新的音频必须为 WAV 格式，采样率 44100，大小不能超过原版（超过会截断）。<br>
     - Sound 0 000110D0：锁定
     - Sound 1 0001678C：新消息通知
     - Sound 2 00022E2C：通话接通/挂断
     - Sound 3 000857AE：通话来电铃声
     - Sound 4 000126E0：解锁

   - `legacy/unmutex.py`：~~旧的多开~~<br>移除 4.0.3+ 互斥锁检测，允许多次启动同一个微信程序。该修改已弃用。<br>不要用于登录多个账号，配置冲突会导致闪退，请用共存。

   - `legacy/revoke.py`：~~旧的防撤回无提示~~<br>抑制 revokemsg 撤回指令消息，消息无法被撤回，没有撤回提示。

## 问题解答

- 无权修改文件？<br>
  以管理员权限运行试试？还不行的话请反馈。

- 运行代码报错了？补丁失效了？<br>
  在 [**议题**](https://github.com/zetaloop/BetterWX/issues) 中反馈。

- 微信 3.9.x 能用吗？<br>
  猜你想找 [huiyadanli/RevokeMsgPatcher](https://github.com/huiyadanli/RevokeMsgPatcher)。

- Linux、macOS 能用吗？<br>
  ~~送我台 mac 电脑我就去学~~ 在学了在学了qwq

- 共存、防撤回这几个特性我可以挑选几个 or 全都要吗？<br>
  可以的，只需执行你要的补丁即可。但是共存必须启用多开。<br>共存版拥有单独的 `Weixin.dll`，你甚至可以让不同的共存版有不同的提示音。

- 本项目的许可证？<br>
  Unlicense，完全放弃任何权利。包括那个图标。

- 特征怎么来的？<br>
  我家猫找的。

- 作者可爱吗？<br>
  很可爱的 OwO，要不要[来看看我做的其他东西](https://github.com/zetaloop)？
