
     ____        _        _       _          ____            _       _ 
    |  _ \  __ _| |_ __ _| | __ _| | _____  / ___|  ___ _ __(_)_ __ | |_ ___
    | | | |/ _` | __/ _` | |/ _` | |/ / _ \ \___ \ / __| '__| | '_ \| __/ __|
    | |_| | (_| | || (_| | | (_| |   <  __/  ___) | (__| |  | | |_) | |_\__ \
    |____/ \__,_|\__\__,_|_|\__,_|_|\_\___| |____/ \___|_|  |_| .__/ \__|___/
                                                              |_|


# datalake
Datalake scripts

## How to use

### Installation

With Python 3.6+:  
```
$ pip install datalake-scripts
$ pip3 install datalake-scripts
```
### Using as a library
see [the following link](tutorial.md)

### Using as a CLI 

The cli can be used with:
```shell script
$ ocd-dtl <command> <parameter>
```
Check `ocd-dtl -h` for help, including the list of commands available.

You can also use a script directly by using the following command: `<script_name> <script_options>`.

> /!\ Make sure to use utf-8 **without BOM** when providing a file (-i option)

## Environment variables

#### Authentication
In case you don't want to enter credential for each commands and you are on a secured terminal, set those variables:  
* `OCD_DTL_USERNAME` email address used to login on Datalake API/GUI.   
* `OCD_DTL_PASSWORD` password used to login on Datalake API/GUI.
> They are independent and one can be used without the other if you wish.

#### Throttling
For throttling the request, those two environment variable can be used:  
* `OCD_DTL_QUOTA_TIME` define, in seconds, the time before resetting the requests limit, *default is 1 second*.   
* `OCD_DTL_REQUESTS_PER_QUOTA_TIME` define the number of request to do at maximum for the given time,  *default is 5 queries*.

> Please don't exceed the quota marked [here](https://datalake.cert.orangecyberdefense.com/api/v2/docs/) for each endpoint

## Cli parameters  

Parameters common and optional for all commands:
> --debug  display more information for debugging purposes   
> -e to change the environment {preprod, prod},  default is **prod**  
> -o will set the output file as the API gives it.  
> -q will quiet the verbosity of the program (but still show errors / warnings)  

For information about each command and more, please check [the documentation directory](https://github.com/cert-orangecyberdefense/datalake/tree/master/docs)
