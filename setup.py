from setuptools import setup, find_packages

with open("README.md", "rt", encoding="utf8") as f:
    readme = f.read()

setup(
    name="optimistic-brainfuck",
    description="Optimistic brainfuck rollup fraud proof generator",
    version="0.0.1",
    long_description=readme,
    long_description_content_type="text/markdown",
    author="protolambda",
    author_email="proto+pip@protolambda.com",
    url="https://github.com/protolambda/optimistic-brainfuck",
    python_requires=">=3.8, <4",
    license="MIT",
    packages=find_packages(),
    py_modules=["obf"],
    tests_require=[],
    extras_require={
        "testing": ["pytest"],
        "linting": ["flake8", "mypy"],
    },
    install_requires=[
        "remerkleable==0.1.24",
        "Click",
    ],
    include_package_data=True,
    entry_points={
        'console_scripts': [
            'obf = obf._cli:cli',
        ],
    },
    keywords=["optimistic", "rollup", "optimism", "fraud-proof", "brainfuck", "ethereum"],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Operating System :: OS Independent",
    ],
)
