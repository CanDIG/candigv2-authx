#!/usr/bin/env python

import setuptools

with open("README.md", "r") as rf:
    long_description = rf.read()

setuptools.setup(
    name="candigv2_authx",
    version="v1.0.0",
    author="Daisie Huang",
    python_requires=">=3.7",
    install_requires=[
        "requests>=2.25.1,<3.0"
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
