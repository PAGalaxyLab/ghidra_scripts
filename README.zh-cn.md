# ghidra_scripts
我们所使用的一些Ghidra逆向分析脚本.

*说明文档的其他语言: [English](README.md), [简体中文](README.zh-cn.md)*

# 安装
在Ghidra脚本管理器中点击"Script Directories", 添加checked out后的repository路径.


# galaxy_utility
其他Ghidra脚本所使用的实用工具。


# trace_function_call_parm_value.py
使用Ghidra P-Code追踪分析函数调用时的传参值。

![Demo pic](docs/images/trace_function_call_parm_value_pic_1.jpg)


# Demo

## wr886nv7_rename_function_with_error_print.py
样例脚本, 利用函数错误输出中的函数名关键字来重命名未定义的函数。
[详细步骤](docs/wr886nv7_rename_function_with_error_print.zh-cn.md)

![Demo pic](docs/images/wr886nv7_rename_function_with_error_print_1.jpg)


# AnalyzeOCMsgSend.py
使用Ghidra脚本分析Objective-C中的MsgSend方法。

![Demo pic](docs/images/analyze_oc_msg_send_pic.png)
