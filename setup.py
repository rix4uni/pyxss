from setuptools import setup, find_packages

def dependencies(imported_file):
    """ __Doc__ Handles dependencies """
    with open(imported_file) as file:
        return file.read().splitlines()

setup(
    name="pyxss",
    packages=find_packages(),
    include_package_data=True,
    entry_points={
        'console_scripts': [
            'pyxss=pyxss.pyxss:main',  # Adjust the import path for main
        ],
    },
    # install_requires=[],  # Add any dependencies if needed
    install_requires=dependencies('requirements.txt')
)
