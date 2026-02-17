
     ____        _        _       _          ____            _       _ 
    |  _ \  __ _| |_ __ _| | __ _| | _____  / ___|  ___ _ __(_)_ __ | |_ ___
    | | | |/ _` | __/ _` | |/ _` | |/ / _ \ \___ \ / __| '__| | '_ \| __/ __|
    | |_| | (_| | || (_| | | (_| |   <  __/  ___) | (__| |  | | |_) | |_\__ \
    |____/ \__,_|\__\__,_|_|\__,_|_|\_\___| |____/ \___|_|  |_| .__/ \__|___/
                                                              |_|


## How to use

Datalake scripts is developed by Datalake developers to help use the Datalake [API](https://datalake.cert.orangecyberdefense.com/api/v3/docs/)

You can use this repository either as a library or as a CLI

### Installation

With Python 3.6+:  
```
$ pip install datalake-scripts
$ pip3 install datalake-scripts
```
### Using as a library
The library requires to first create a Datalake instance and then to use the defined Classes' methods

The library tutorial is available in [the following link](https://github.com/cert-orangecyberdefense/datalake/blob/master/tutorial.md)

Example : 
```python
from datalake import Datalake, AtomType, Output

dtl = Datalake(username='username', password='password')
dtl.Threats.lookup(
    atom_value='mayoclinic.org',
    atom_type=AtomType.DOMAIN,
    hashkey_only=False,
    output=Output.JSON
)
```




### Using as a CLI 

The cli can be used with:
```shell script
$ ocd-dtl <command> <parameter>
```
Check `ocd-dtl -h` for help, including the list of commands available.

You can also use a script directly by using the following command: `<script_name> <script_options>`.

> /!\ Make sure to use utf-8 **without BOM** when providing a file as input (`-i, --input` parameter)

#### Cli parameters  

Common parameters for all commands:  
* `-e, --env <preprod|prod>` :   Datalake environment. Default is **prod**  
* `-o, --output <OUTPUT_PATH>` : will set the output file as the API gives it.  No default
* `-D, --debug`  : will raise the verbosity of the program (by displaying additional DEBUG messages). Default log level is INFO
* `-q, --quiet` : will quiet the verbosity of the program (but will still show ERROR / WARNING messages). Default log level is INFO

Commands can also have additionary mandatory or optional parameters

For information about each command and more, please check [the documentation directory](https://github.com/cert-orangecyberdefense/datalake/tree/master/docs)


### Environment variables

#### Authentication

There are two methods of authentication:
- The first one is the use of the username and password. Every request to the API, will then use fresh tokens periodically created with these credentials.
- The second one is the use of a long term token. You can create long term token through the GUI, it can have more restricted permissions than your account. You can create several long term tokens for one account. 

In case you don't want to enter credentials for each commands and you are on a secured terminal, set those variables:  
* `OCD_DTL_LONGTERM_TOKEN` a long term token associated to your Datalake account.
Please note that if this variable is set, then the long term token will be used for every request to the Datalake API, even if you set the username and passsword environment variables below. This is important because some endpoints / requests do not accept long term tokens but need fresh tokens (ie a Datalake instance with username and password). Check for the need of fresh tokens in each endpoint description [here](https://datalake.cert.orangecyberdefense.com/api/v3/docs/)

or

* `OCD_DTL_USERNAME` email address used to login on Datalake API/GUI.   
* `OCD_DTL_PASSWORD` password used to login on Datalake API/GUI.
> These last two are independent and one can be used without the other if you wish.

#### Using a Proxy

You can set up following environment variables : 

* `HTTP_PROXY`
* `HTTPS_PROXY`

We use the format accepted by the requests python library. 
See its documenation for other possible kinds of proxy to set up.


#### Throttling and retries
For throttling the requests, those two environment variables can be used:  
* `OCD_DTL_QUOTA_TIME` defines, in seconds, the time before resetting the requests limit, *default is 1 second*.   
* `OCD_DTL_REQUESTS_PER_QUOTA_TIME` defines the number of request to do at maximum for the given time,  *default is 5 queries*.
We recommend to lower the `OCD_DTL_REQUESTS_PER_QUOTA_TIME` value, if you encounter too many 429 errors.

> Please don't exceed the quota marked [here](https://datalake.cert.orangecyberdefense.com/api/v3/docs/) for each endpoint

Only network errors and HTTP response code 429, 500, 502, 503 and 504 trigger retries. You may control the number of retries using the environment variable `OCD_DTL_MAX_RETRIES`, which defaults to 3.

### Contributing

To develop on this repository, please refer to [this file](https://github.com/cert-orangecyberdefense/datalake/tree/master/CONTRIBUTING.md) 