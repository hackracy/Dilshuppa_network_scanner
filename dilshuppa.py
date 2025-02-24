from setuptools import setup

setup(
    name='Dilshuppa_network_scanner',
    version='1.1',
    author='Dilshuppa',
    author_email='your_email@example.com',
    description='A network scanner tool for detecting devices, open ports, services, vulnerabilities, and more.',
    packages=['dilshuppa_network_scanner'],
    install_requires=[
        'nmap',
        'scapy',
        'psutil',
        'requests',
    ],
    entry_points={
        'console_scripts': [
            'dilshuppa_network_scanner=Dilshuppa_network_scanner:main',
        ],
    },
)
