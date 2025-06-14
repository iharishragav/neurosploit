from setuptools import setup, find_packages

setup(
    name='neurosploit',
    version='2.0.0',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'pyfiglet',
        'termcolor',
        'requests',
        'dnspython',  # Fixed typo from 'dnspyhton'
        'python-whois',  # Fixed from 'whois' to match import
        'urllib3',
        'certifi',
    ],
    entry_points={
        'console_scripts': [
            'neurosploit = neurosploit.cli:main',
        ],
    },
    package_data={
        'neurosploit': ['data/*.txt', 'prompts/*.txt']
    },
    author='Kamalesh',
    author_email='ragavhrxh@gmail.com',
    description='AI-powered red team recon assistant',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/iharishragav/neurosploit',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
)