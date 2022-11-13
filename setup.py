from setuptools import setup

setup(
    name='b3a',
    version='0.1.0',
    py_modules=['b3a'],
    install_required=[
        'Click'
    ],
    entry_points={
        'console_scripts': [
            'b3a = b3a:cli'
        ]
    }
)