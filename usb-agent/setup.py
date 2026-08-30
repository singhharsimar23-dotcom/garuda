from setuptools import setup, find_packages

setup(
    name="garuda-usb-agent",
    version="0.3.0",
    description="GARUDA USB Portable & Air-Gapped Physical Host Defense Agent",
    packages=find_packages(),
    install_requires=[
        "pydantic>=2.0.0",
    ],
    entry_points={
        "console_scripts": [
            "garuda-usb-agent=garuda_usb_agent.agent_main_usb:main",
        ],
    },
)
