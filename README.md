# icon_getinfo
**icon_getinfo** is a simple pkg, 
+ ICON blockchain Network node get information

# How to Pre-install 
## Python
+ python >= 3.7
+ pip install -r requirement.txt

## pyenv install
+ Link: [pyenv_install][pyenv_install]

[pyenv_install]: https://louky0714.tistory.com/156 "Go Install PAGE"

# How to install
```console
$ pip3 install icon-getinfo
```

# Usage
$ ./icon_getinfo -h
```console
usage: icon_getinfo [-h] [-u URL] [--duration_time] [--no-trunc] [--showlog] [--filter FILTER [FILTER ...]]   
                       {chain,chain_detail,chain_inspect,system,all,   
                        all_chain,all_chain_inspect,all_chain_detail,all_system,all_node}

Get icon node information

positional arguments:
  {chain,chain_detail,chain_inspect,system,all,all_chain,   
   all_chain_inspect,all_chain_detail,all_system,all_node}
                        Icon Network get information mode

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL
  --duration_time       Show Duration of time
  --no-trunc            Don't truncate output
  --showlog             Show running log
  --filter FILTER [FILTER ...], -f FILTER [FILTER ...]
                        Out put print filter
```

# Get Single node chain info

```console
$ ./icon_getinfo [-u node_URL or node_IP] chain
```

# Get Single node chain detail(or inspect) info

```console
$ ./icon_getinfo [-u node_URL or node_IP] chain_detail(or chain_inspect)
```

# Get Single node system info

```console
$ ./icon_getinfo [-u node_URL or node_IP] system
```

# Get Single node chain + system info

```console
$ ./icon_getinfo [-u node_URL or node_IP] all
```


# Get All network node chain or chain_detail(or inspect) info
```console
$ ./icon_getinfo [-u node_URL or node_IP] [all_chain|all_chain_detail(or all_chain_inspect)]
```

# Get All network node system info
```console
$ ./icon_getinfo [-u node_URL or node_IP] all_system
```

# Get All network node chain + system info
```console
$ ./icon_getinfo [-u node_URL or node_IP] all_node
```

# Options
```console
  -h, --help            show this help message and exit
  -u URL, --url URL
  -v, --version         Show Version
  --duration_time       Show Duration of time
  --notrunc             Don't truncate output
  --showlog             Show running log
  --filter FILTER [FILTER ...], -f FILTER [FILTER ...]
                        Out put print filter
```

