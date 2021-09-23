# deserter
## What is deserter?
`deserter` is the first of its kind *targeted* DNS cache poisoner. It is capable of DNS cache poisoning *without* bruteforcing the target ID and source port - instead, it sniffs out DNS probes and uses the information inside to craft poisoned responses and send them back to the target.

In order for it to work, the attacker needs to be on the same network as the victim. Sometimes, *arp spoofing* may also be required - usually on physical connections through Ethernet.

## Installation
You need to clone this repo with its submodule:
```bash
git clone --recurse-submodules https://github.com/b4ckslash0/deserter
```
```bash
┌──(backslash0@kali)-[~/dev/test]-[]
└─$ git clone --recurse-submodules https://github.com/b4ckslash0/deserter
Cloning into 'deserter'...
remote: Enumerating objects: 125, done.
remote: Counting objects: 100% (125/125), done.
remote: Compressing objects: 100% (89/89), done.
remote: Total 125 (delta 36), reused 107 (delta 21), pack-reused 0
Receiving objects: 100% (125/125), 30.41 KiB | 1.05 MiB/s, done.
Resolving deltas: 100% (36/36), done.
Submodule 'external/PcapPlusPlus' (https://github.com/seladb/PcapPlusPlus) registered for path 'external/PcapPlusPlus'
Cloning into '/home/backslash0/dev/test/deserter/external/PcapPlusPlus'...
remote: Enumerating objects: 15076, done.        
remote: Counting objects: 100% (619/619), done.        
remote: Compressing objects: 100% (472/472), done.        
remote: Total 15076 (delta 269), reused 282 (delta 135), pack-reused 14457        
Receiving objects: 100% (15076/15076), 83.19 MiB | 2.06 MiB/s, done.
Resolving deltas: 100% (10354/10354), done.
Submodule path 'external/PcapPlusPlus': checked out '5f43c3d0545bebcc71cc3fa149c200a081784008'
```

The tool depends on [PcapPlusPlus](https://github.com/seladb/PcapPlusPlus), for packet capturing and crafting, and [argparse](https://github.com/p-ranav/argparse), for command-line argument parsing.

Now, change your directory to the cloned repository and then into the `scripts` directory. Change the permission for execution on the `install.sh` file and run it:
```bash
cd deserter/scripts
```
```bash
chmod +x install.sh
```
```bash
./install.sh
```

The tool will build and compile into the `deserter/build` directory. After installation you can use
```bash
./deserter --help
```
for more information. 

Note, the tool requires sudo permissions to be run.

## TODOs:
- add Windows support
- implement proper packet filtering
- fix a random segmentation fault that sometimes occurs (will probaby go away with proper packet filtering)
- use asynchronous packet capturing