
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
```

### Using a script

The cli can be used with:
```shell script
$ ocd-dtl <command> <parameter>
```
Check `ocd-dtl -h` for help, including the list of commands available.

You can also use a script directly by using the following command: `<script_name> <script_options>`.

> /!\ Make sure to use utf-8 **without BOM** when providing a file (-i option)

## Environment variables

#### Throttling
For throttling the request, those two environment variable can be used:  
* `OCD_DTL_QUOTA_TIME` define, in seconds, the time before resetting the requests limit, *default is 1 second*.   
* `OCD_DTL_REQUESTS_PER_QUOTA_TIME` define the number of request to do at maximum for the given time,  *default is 5 queries*

> Please don't exceed the quota marked [here](https://datalake.cert.orangecyberdefense.com/api/v1/docs/) for each endpoint

## More documentation

Please check [the documentation directory](docs)