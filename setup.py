from setuptools import setup, find_packages

setup(
    name="qtrace",
    version="0.1.0",
    python_requires=">=3.8",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "qtrace = qtrace.__main__:main",
        ]
    },
    install_requires=[],
    dependency_links=[],
)
