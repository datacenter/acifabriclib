################################################################################
#             _    ____ ___ _____     _          _      _     _ _              #
#            / \  / ___|_ _|  ___|_ _| |__  _ __(_) ___| |   (_) |__           #
#           / _ \| |    | || |_ / _` | '_ \| '__| |/ __| |   | | '_ \          #
#          / ___ \ |___ | ||  _| (_| | |_) | |  | | (__| |___| | |_) |         #
#         /_/   \_\____|___|_|  \__,_|_.__/|_|  |_|\___|_____|_|_.__/          #
#                                                                              #
#                       === ACI Fabric Setup Library ===                       #
#                                                                              #
################################################################################
#                                                                              #
# [+] Written by:                                                              #
#  |_ Luis Martin (lumarti2@cisco.com)                                         #
#  |_ CITT Software CoE.                                                       #
#  |_ Cisco Advanced Services, EMEAR.                                          #
#                                                                              #
################################################################################
#                                                                              #
# Copyright (c) 2015-2016 Cisco Systems                                        #
# All Rights Reserved.                                                         #
#                                                                              #
#    Unless required by applicable law or agreed to in writing, this software  #
#    is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF   #
#    ANY KIND, either express or implied.                                      #
#                                                                              #
################################################################################

import os
from setuptools import setup

base_dir = os.path.dirname(__file__)

about = {}
with open(os.path.join(base_dir, "acifabriclib", "__about__.py")) as f:
    exec(f.read(), about)

setup(
    name=about["__title__"],
    version=about["__version__"],
    packages=["acifabriclib"],
    author=about["__author__"],
    author_email=about["__email__"],
    url=about["__uri__"],
    license=about["__license__"],
    install_requires=["requests"],
    description=about['__summary__'],
)
