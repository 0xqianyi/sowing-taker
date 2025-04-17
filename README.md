1. 执行安装命令:
   ```bash
   wget -O install_taker.sh https://raw.githubusercontent.com/0xqianyi/sowing-taker/refs/heads/main/install_taker.sh && sed -i 's/\r$//' install_taker.sh && chmod +x install_taker.sh && ./install_taker.sh
   ```
1. 编辑私钥文件:
   ```bash
   nano private_keys.txt
   ```
1. 示例:
   ```bash
   abc123...def456
   789xyz...ghi012
   ```
4.保存（Ctrl+O，Enter），退出（Ctrl+X）。

1. 编辑代理文件:
   ```bash
   nano proxies.txt
   ```
1. 示例:
   ```bash
   http://IP:PORT
   socks5://IP:PORT
   ```
