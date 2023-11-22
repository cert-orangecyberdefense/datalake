# Installation for local development

You will need Python 3.6+ in order to execute the scripts.  

# Adding a new lib function 

To add a new script, simply create a new file in the appropriate file/class under directory `./datalake/endpoints`.  
If you create a new class, do not forget to add it to `./datalake/datalake.py`.  
And create thorough tests in `./tests/lib/test_{class_name}.py` (think of edge cases)  
You can also test it manually (see chapter below)

# Adding a new script / cli command

To add a new script, simply create a new file in `./src/scripts/{my_script_name.py}`.  
And add a new function to the [cli file](../datalake_scripts/cli.py).  
And add your new function in the test file `./tests/scripts/test_cli.py`  
And do not forget to test this new comand manually (see chapter below)

# Adding new utils functions

Functions to be used by several commands or library functions can be added in :
- `./datalake/common` 
- `./datalake_scripts/common`
- `./datalake_scripts/helper_scripts`

They can have their own tests in directory `./tests/common`


# Tests

## Automatic tests

The easiest way to run automatic tests is to launch the make command : 
```shell script
make test_dev_env
```

You can also only run a specific test by launching the command : 
```shell script
make test_dev_env path=tests/<test_directory>/<test_file>.py::<test_function>
```
*Example*
```shell script
make test_dev_env path=tests/scripts/test_csv_builder.py::test_single_threat_no_details
```

Or you can also run  :
```shell script
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
make test
```
**Notes**: 
- to leave virtual environment, run `deactivate`  
- you can here as well add a path to the `make test` command to run only a specific test


## Manual tests for cli commands

But please be aware than the tests on Cli commands only test the calls of the script function. 

So when developing/editing a new command, please test several cases 

First install and enter in a virtual environment :
```shell script
python3 -m venv .venv
source .venv/bin/activate
```
**Note**: to leave virtual environment, run `deactivate`

and then run the commands :
```shell script
pip install -r requirements.txt
make test
pip install .
```
You can then launch the Cli commands : 
```shell script
$ ocd-dtl <command> <parameter>
```

## Manual tests for lib functions

First install and enter in a virtual environment :
```shell script
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Then create a script to test new functions : 
```shell script
touch test_script.py
vi test_script.py
python3 test_script.py
```
***Example***:
```shell script
from datalake import Datalake, Output

dtl = Datalake(username='<email>', password='<password>', env='preprod')

task = dtl.BulkSearch.create_task(for_stix_export=True, query_hash='eeb25f838e59f2be41a2631bc440fb10')
stix = task.download_sync_stream_to_file(output=Output.STIX_ZIP, output_path="stix_export.zip")
```

Then run it : 
```shell script
python3 test_script.py
```
**Note**: Be careful to not include in your commit this test script, especially if it contains your login/password
