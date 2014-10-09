from setuptools import setup, find_packages

version = '1.6'

long_description = (
    open('README.txt').read()
    + '\n' +
    'Contributors\n'
    '============\n'
    + '\n' +
    open('CONTRIBUTORS.txt').read()
    + '\n' +
    open('CHANGES.txt').read()
    + '\n')

setup(name='gummanager.libs',
      version=version,
      description="",
      long_description=long_description,
      # Get more strings from
      # http://pypi.python.org/pypi?%3Aaction=list_classifiers
      classifiers=[
          "Programming Language :: Python",
      ],
      keywords='',
      author='Carles Bruguera',
      author_email='carles.bruguera@upcnet.es',
      url='http://svn.plone.org/svn/collective/',
      license='gpl',
      packages=find_packages(exclude=['ez_setup']),
      namespace_packages=['gummanager'],
      include_package_data=True,
      zip_safe=False,
      install_requires=[
          'setuptools',
          # -*- Extra requirements: -*-
          'python-ldap',
          'requests',
          'pyquery',
          'sh',
          'configobj',
          'circus',
          'humanize',
          'pymongo',
          'maxclient',
          'websocket-client',
          'stomp.py',
          'maxcarrot',
          'gevent',
          'xlrd'
      ],
      entry_points="""
      # -*- Entry points: -*-
      """,
      )
