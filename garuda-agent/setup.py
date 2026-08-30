from setuptools import setup, find_packages

setup(
    name="garuda-agent",
    version="0.1.0",
    description="GARUDA Host Telemetry Agent for Physical and Kernel Execution Monitoring",
    author="GARUDA Cyber Defense Team",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "pydantic>=2.0.0",
        "pydantic-settings>=2.0.0",
        "typing-extensions>=4.0.0",
    ],
    entry_points={
        "console_scripts": [
            "garuda-agent=garuda_agent.agent_main:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: POSIX :: Linux",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
    ],
)
