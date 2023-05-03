#!/usr/bin/env python

import setuptools

with open("README.md", "r") as rf:
    long_description = rf.read()

setuptools.setup(
    name="candigv2_authx",
    version="v1.1.0",
    author="Daisie Huang",
    python_requires=">=3.7",
    install_requires=[
        "requests>=2.25.1,<3.0",
        "minio>=7.1.7",
        "pytest==7.2.0",
        "PyJWT>=2.6.0",
        "cryptography>=3.4.0"
    ],

    description="Common authentication and authorization methods for CanDIGv2",
    long_description=long_description,
    long_description_content_type="text/markdown",

    packages=setuptools.find_packages(),
    include_package_data=True,

    url="https://github.com/CanDIG/candigv2-authx",
    license="LGPLv3",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)",
        "Operating System :: OS Independent"
    ]
)
