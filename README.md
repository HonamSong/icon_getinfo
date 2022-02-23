# icon_getinfo

**icon_getinfo** is a simple pkg, 
ICON blockchain Network node get information

# Usage

```console
$ ./icon_getinfo -h
usage: icon_getinfo.py [-h] [-m {chain,chain_detail,chain_inspect,system,all,all_chain,all_chain_inspect,all_chain_detail,all_system,all_node}] 
                            [-u URL] [--duration_time] [--notrunc] [--showlog]

Get icon node information

optional arguments:
  -h, --help            show this help message and exit
  -m {chain,chain_detail,chain_inspect,system,all,all_chain,all_chain_inspect,all_chain_detail,all_system,all_node}, --mode {chain,chain_detail,chain_inspect,system,all,all_chain,all_chain_inspect,all_chain_detail,all_system,all_node}
                        Get mode type
  -u URL, --url URL
  --duration_time       Show Duration of time
  --notrunc             Don't truncate output
  --showlog             show running log
```

# Get Single node chain info

```console
$ ./icon_getinfo [-u node_URL or node_IP] -m chain
```

# Get Single node chain deatil(inspect) info

```console
$ ./icon_getinfo [-u node_URL or node_IP] -m [chain_detail | chain_inspect]
```

# Get Single node system info

```console
$ ./icon_getinfo [-u node_URL or node_IP] -m system
```

# Get Single node chain + system info

```console
$ ./icon_getinfo [-u node_URL or node_IP] -m all
```


# Get All network node chain or chain_detail(inspect) info
```console
$ ./icon_getinfo [-u node_URL or node_IP] -m [all_chain | [all_chain_detail|all_chain_inspect]]
```

# Get All network node system info
```console
$ ./icon_getinfo [-u node_URL or node_IP] -m all_system
```

# Get All network node chain + system info
```console
$ ./icon_getinfo [-u node_URL or node_IP] -m all_node
```



