#!/usr/bin/env python2
from setuptools import setup, find_packages

with open("README.md", "r") as f:
    long_description = f.read()

setup(
    name = "security_credential_helper",
    version = "1.0",
    description = "A helper package for managing security credentials",
    long_description=long_description,
    long_description_content_type="text/markdown",
    license="Apache License 2.0",
    author = "Jeffrey Smith",
    author_email = "jeffrey.smith@acceldata.io",
    url="https://github.com/JeffreySmith/security_credential_helper",
    project_urls={
        "Source": "https://github.com/JeffreySmith/security_credential_helper",
    },
    packages = find_packages(),
    install_requires = ["typing==3.10.0", "pathlib2==2.3.7.post1", "enum34==1.1.10"],
    entry_points={
        "console_scripts": [
            "security_credential_helper=security_credential_helper:interactive",
        ],
    },
    zip_safe=False,
    python_requires = ">= 2.7, <3",
    classifiers=[
        "Programming Language :: Python :: 2.7",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries",
    ],
    keywords="security credentials helper",
)
