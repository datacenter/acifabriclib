             _    ____ ___ _____     _          _      _     _ _     
            / \  / ___|_ _|  ___|_ _| |__  _ __(_) ___| |   (_) |__  
           / _ \| |    | || |_ / _` | '_ \| '__| |/ __| |   | | '_ \ 
          / ___ \ |___ | ||  _| (_| | |_) | |  | | (__| |___| | |_) |
         /_/   \_\____|___|_|  \__,_|_.__/|_|  |_|\___|_____|_|_.__/ 
                                                                               
        == Library to ease initial deployment of a Cisco ACI Fabric ==
     
Introduction
============

ACIFabricLib is a Python library to ease initial deployment of an ACI fabric. 
The library provides a simple set of classes to perform initial tasks on 
a fabric such as creating PortChannels, VPCs, Interface policies, VLAN pools,
VXLAN pools, Multicast Pools, etc.

The library by itself does nothing. It is meant to be consumed by a Python
application that uses it to create and push new objects into an ACI fabric.


Installation
============

1. Download the source code
    - **Option A**: Cloning the repository directly
        - $ git clone https://engci-gitlab-gpk.cisco.com/lumarti2/acifabriclib.git
    - **Option B**: Downlading it as a ZIP file and decompressing it
        - Linux/Mac:
            - $ wget http://engci-gitlab-gpk.cisco.com/lumarti2/acifabriclib/repository/archive.zip --no-check-certificate
            - $ unzip archive.zip
        - Windows:
            - Download the file with an Internet browser and decompress it to your local hard drive.
                - http://engci-gitlab-gpk.cisco.com/lumarti2/acifabriclib/repository/archive.zip
2. Install the library
    - Open a command-line console
    - Go to the directory where the source code was uncompressed (the one where the setup.py file is) and run: 
        - $ python3 setup.py install

3. Now you can start creating your scripts using the library. Just import
   it in your code using "from acifabriclib import *" at the beginning of your
   source code file.

Author
======
Luis Martin, CITT EMEAR, Cisco Advanced Services (lumarti2@cisco.com)

                                            