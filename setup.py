

# setup.py
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = fh.read().splitlines()

setup(
    name="zk-vpn",
    version="0.1.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="Zero-Knowledge VPN with ZK-SNARK proofs",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/username/zk-vpn",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security :: Cryptography",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "zkvpn=zkvpn.cli.main:main",
            "zkvpn-node=zkvpn.nodes.server:main",
            "zkvpn-dashboard=zkvpn.web.dashboard:main",
        ],
    },
    include_package_data=True,
    package_data={
        "zkvpn": ["config/*.yml", "circuits/*.circom"],
    },
)


    entry_points={
        "console_scripts": [
            "zkvpn=zkvpn.cli.main:main",
            "zkvpn-node=zkvpn.cli.main:cli",  # Alias
        ],
    },
    install_requires=[
        # ... existing requirements ...
        "click>=8.1.0",
        "rich>=13.5.0",
        "humanize>=4.9.0",
        "pyperclip>=1.8.2",
        "qrcode>=7.4.0",
        "pillow>=10.0.0",  # Required for QR codes
    ],
