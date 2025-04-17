 1. 执行安装命令:
   ```bash
   wget -O install_taker.sh https://raw.githubusercontent.com/0xqianyi/sowing-taker/refs/heads/main/install_taker.sh && sed -i 's/\r$//' install_taker.sh && chmod +x install_taker.sh && ./install_taker.sh
   ```
 2. 进入taker_quest目录:
   ```bash
   cd /root/taker_quest
   ```
 3. 激活虚拟环境:
   ```bash
   source venv/bin/activate
   ```
 4. 编辑私钥文件:
   ```bash
   nano private_keys.txt
   ```
 5. 示例:
   ```bash
   abc123...def456
   789xyz...ghi012
   ```
 7. 编辑代理文件，私钥1对应代理1登录（如需本地直连代理对应行数需要留空）:
   ```bash
   nano proxies.txt
   ```
 8. 示例:
   ```bash
   http://IP:PORT
   socks5://IP:PORT
   ```
 10. 新建会话:
   ```bash
   screen -S takerbot
   ```
 10. 运行脚本:
   ```bash
   python taker_checkin.py
   ```
  --------------------------------------------------------
 10. 删除脚本:
   ```bash
   deactivate
   rm -rf ~/taker_quest
   ```
