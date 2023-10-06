用法：
```
入域主机
python 1.py a.b/Administrator 12345 192.168.1.1

python 1.py a.b/Administrator :nthash 192.168.1.1

工作组

python 1.py ./Administrator 12345 192.168.1.1

python 1.py ./Administrator :nthash 192.168.1.1


最后有一个可选项，是编码方式

文件上传命令格式：
	up$本地文件路径$远程文件路径
	
文件下载命令格式：
	down$远程文件路径$本地文件路径
  
命令执行：
	直接输入命令即可

输入q清理并退出
```

# 票据认证的支持

如果你已经有了现成的TGS或者TGT票据，只需要设置环境变量KRB5CCNAME, 然后按照如下方法使用即可


```
a.lab/Administrator doesnotmatter_just_a_place_holder 目标IP [codec] targetFQDN 域控IP
```
比如：

```
a.lab/Administrator just_a_place_holder 192.168.159.156 GBK adc.a.lab 192.168.159.156
```
或者不指定编码类型
```
a.lab/Administrator just_a_place_holder 192.168.159.156 adc.a.lab 192.168.159.156
```
