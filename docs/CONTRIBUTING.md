# Contribute


### Installation for local development

You will need Python 3.6+ in order to execute the scripts.  
First install a virtual environment and then run the command `pip install -r requirements.txt`.

### Using a script

The easiest way is to be in the virtual environment and run commands with:
```shell script
ocd-dtl <command> <parameter>
```
Check `ocd-dtl -h` for help, including the list of commands available.

> /!\ Make sure to use utf-8 **without BOM** when providing a file (-i option)


### Adding a new script

To add a new script, simply create a new file in `./src/scripts/{my_script_name.py}`.  
And add a new function to the [cli file](../datalake_scripts/cli.py).  

### Tests

Run tests with `python -m pytest`
