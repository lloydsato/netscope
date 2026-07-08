from setuptools import setup, find_packages

setup(
    name="netscope",
    version="0.2.0",
    description="Local network discovery, fingerprinting, traffic analysis, monitoring, and security reporting.",
    packages=find_packages(),
    include_package_data=True,
    package_data={"netscope": ["data/*.json.gz"]},
    install_requires=["scapy>=2.5.0"],
    entry_points={"console_scripts": ["netscope=netscope.cli:main"]},
    python_requires=">=3.8",
)
