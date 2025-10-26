from setuptools import setup, find_packages

setup(
    name='nmap_automator',
    version='2.0.0',
    packages=find_packages(),
    install_requires=[
        'colorama',
        'tqdm',
    ],
    author='mosesjuju',
    description='Automated Nmap and Masscan scanning tool',
    python_requires='>=3.7',
)
