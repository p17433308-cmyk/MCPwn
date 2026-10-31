from setuptools import setup, find_packages

setup(
    name="mcpwn",
    version="1.0.0",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[],
    entry_points={"console_scripts": ["mcpwn=mcpwn.cli:main"]},
    author="Dr. Sapna VM, Prajwal Chowdary M, Prasad B Honnavalli",
    description="MCPwn — Offensive Security Framework for AI Agent Protocols",
)
