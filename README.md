[交付材料](https://github.com/wqreytuk/JiaoFu/blob/main/%E6%A8%AA%E5%90%91%E7%A7%BB%E5%8A%A8%E5%B7%A5%E5%85%B7.7z)

[中文](https://github.com/wqreytuk/py135/blob/main/readme-ZH.md)


execute command, upload and download file with [TSCH](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/d1058a28-7e02-4948-8b8d-4a347fa64931)

usage:

```
computers in Domain
python 1.py a.b/Administrator 12345 192.168.1.1 [codec]

python 1.py a.b/Administrator :nthash 192.168.1.1 [codec]

computers in WorkGroup

python 1.py ./Administrator 12345 192.168.1.1 [codec]

python 1.py ./Administrator :nthash 192.168.1.1 [codec]
```

file upload:

```
up$local_file$remote_file
```

file download:

```
down$remote_file$local_file
```

command execute:

```
just input the command you want to execute
```
clear and exit:

```
just input q
```
# kerberos auth

if you already have a TGT or TGS, just set the ENV variable KRB5CCNAME, and the use it like this:


```
a.lab/Administrator doesnotmatter_just_a_place_holder target_ip [codec] targetFQDN dcIP
```
eg:

```
a.lab/Administrator just_a_place_holder 192.168.159.156 GBK adc.a.lab 192.168.159.156
```
