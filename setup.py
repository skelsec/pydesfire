from setuptools import setup, find_packages

setup(
	name='pydesfire',
	version='0.1',
	packages=find_packages(exclude=['tests*','examples*']),
	license='MIT',
	description='DESFire library for python',
	long_description=open('README.txt').read(),
	install_requires=['pycrypto','enum34','pyscard'],
	url='https://github.com/skelsec/pydesfire',
	author='Tamas Jos',
	author_email='pydesfire@skelsec.com'
)