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
