#!/usr/bin/env python3
"""Trae 企业版反代网关入口。

用法：
    python gateway.py                 # 读 config.json 的 host/port
    python gateway.py --port 57896    # 覆盖端口
    TRAE_ENT_GATEWAY_HOME=./data python gateway.py   # 指定数据目录
"""

from trae_ent_gateway.app import main

if __name__ == "__main__":
    main()
