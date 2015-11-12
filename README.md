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

Author
======
Luis Martin, CITT EMEAR, Cisco Advanced Services (lumarti2@cisco.com)

                                            