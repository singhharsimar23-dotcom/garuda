from setuptools import setup, find_packages
import os

long_description = "GARUDA Host Telemetry Daemon for Physics & Kernel Monitoring"
if os.path.exists("README.md"):
    with open("README.md", "r", encoding="utf-8") as fh:
        long_description = fh.read()

setup(
    name="garuda-agent",
    version="0.1.0",
    description="GARUDA Host Telemetry Daemon for Physics & Kernel Monitoring",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="GARUDA Cyber Defense Team",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "toml>=0.10.2",
        "httpx>=0.24.0",
        "numpy>=1.22.0",
        "scikit-learn>=1.2.0",
    ],
    entry_points={
        "console_scripts": [
            "garuda-agent=garuda_agent.daemon:main",
            "garuda-service=garuda_agent.service:main",
        ],
    },
    package_data={
        "": ["fixtures/*.json"],
    },
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: POSIX :: Linux",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
    ],
)
