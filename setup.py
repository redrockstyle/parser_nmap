from setuptools import setup, find_packages

setup(
    name='parser_nmap',
    version='1.5.2',
    url="https://github.com/redrockstyle/parser_nmap",
    author="RedRockStyle",
    description="TCP Parser NMAP Normal output (-oN) v1.5.2",
    packages=find_packages(),
    python_requires=">=3.6",
    zip_safe=False,
    entry_points={
        'console_scripts':
            ['parser = parser_nmap.parser_nmap:main']
    }
)
