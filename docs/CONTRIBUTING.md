# Contribute


### Installation for local development

You will need Python 3.6+ and Pipenv in order to execute the scripts.  
To install the virtual environment run the command `pipenv install`.

### Using a script

The easiest way is to be in a virtual environment (with `pipenv shell`) and run commands with:
```shell script
ocd-dtl <command> <parameter>
```
Check `ocd-dtl -h` for help, including the list of commands available.

You can also use a script directly by using the following command: `pipenv run {my_script_name} {my_script_options}`.
Or by launching the virtual env shell with `pipenv shell` and then `{my_script_name} {my_script_options}`.

> /!\ Make sure to use utf-8 **without BOM** when providing a file (-i option)


## Adding a new script

To add a new script, simply create a new file in `./src/scripts/{my_script_name.py}`.
Add the following line in `./setup.py`:
```
    entry_points={
        'console_scripts': (
        {my_script_name} = src.scripts.{my_script_name}:main,
        xxxxxxxxxxxxxxxx = src.scripts.xxxxxxxxxxxxxxxx:main,
        )
    }
```
And add a new function to the [cli file](src/cli.py).
  
> You will need to reinstall your environement by running `pipenv install`.