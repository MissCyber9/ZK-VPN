from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [
        line.strip() for line in fh
        if line.strip() and not line.startswith("#")
    ]

setup(
    name="zk-vpn",
    version="0.1.0",
    description="Zero-Knowledge VPN prototype (WireGuard + simulated ZK proofs)",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/MissCyber9/ZK-VPN",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security :: Cryptography",
        "Programming Language :: Python :: 3",
    ],
    python_requires=">=3.9",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "zkvpn=zkvpn.cli.main:main",
        ],
    },
    include_package_data=True,
    package_data={"zkvpn": ["circuits/*.circom"]},
)
