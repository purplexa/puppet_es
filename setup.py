from setuptools import setup

setup(name='puppet_es',
      version='0.1.0',
      description='Tooling for submitting JSON dumps of Puppet reports to ElasticSearch',
      url='http://github.com/thrnio/puppet_es',
      author='Ryan Whitehurst',
      license='Apache License 2.0',
      classifiers=['License :: OSI Approved :: Apache Software License'],
      install_requires=['elasticsearch'],
      tests_require=['mock', 'pytest'],
      packages=['puppet_es'],
      entry_points={'console_scripts': 'send_report_to_es = puppet_es:main'})