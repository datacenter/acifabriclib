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


Using the Library
=================

- Create the main skeleton for the code

```
    from acifabriclib import *

    # Start of the execution
    if __name__ == "__main__":

        print("Starting the app")
        # Insert your code here
```


- Instance a Fabric object and create an authenticated session with the fabric

```
        # Instance a new Fabric object
        f = fabriclib.Fabric("https://10.49.0.100", "admin", "pwd9999!")

        # Connect and authenticate
        f.connect()
```


- Now create a new object, for example, a VPC interface.

```
        iface = VPC("VPC-Towards-Cat6509")
```

- Set up it's properties

```
        # Specify which interfaces belong to it
        iface.add_port(101, 1, 37)
        iface.add_port(102, 1, 53)
```

- Make changes effective on the fabric

```
        # Push the changes to the fabric
        f.push_to_apic(iface)
```

- Have a look at the fabric. There should be a complete set of policies that
create the VPC (switch profiles, interface policy group, interface profile, etc)

- Similar steps can be followed for the rest of classes offered by the library.
  Here are some examples:

```
        # Create a VLAN Pool
        v = fabriclib.VLANPool("Server-VLANs")
        v.add_range(100,399)
        v.add_range(500,550)
        f.push_to_apic(v)

        # Create a VXLAN Pool
        v = fabriclib.VXLANPool("Ext-VXLAns")
        v.add_range(30000,30100)
        f.push_to_apic(v)

        # Create a Multicast Address Pool
        v = fabriclib.MulticastPool("Ext-Multicast")
        v.add_range("224.0.0.0", "224.0.0.255")
        v.add_range("224.1.0.0", "224.3.255.255")
        f.push_to_apic(v)
```

Author
======
Luis Martin, CITT EMEAR, Cisco Advanced Services (lumarti2@cisco.com)
http://bock-bock.cisco.com/~lumarti2/
                                            