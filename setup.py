from setuptools import setup, find_packages

setup(
    name="netscope",
    version="0.4.0",
    description="Network discovery, service/version fingerprinting, offline CVE correlation, "
                "TLS/weak-auth auditing, passive threat detection, and exportable findings.",
    packages=find_packages(exclude=["tests", "tests.*"]),
    include_package_data=True,
    package_data={"netscope": ["data/*.json.gz"]},
    install_requires=["scapy>=2.5.0"],
    entry_points={"console_scripts": ["netscope=netscope.cli:main"]},
    python_requires=">=3.8",
)
