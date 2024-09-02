# Add new threats

### Examples

To add new threats from file.

From TXT file:

    100.100.100.1
    100.100.100.2
    100.100.100.3
    100.100.100.4
    100.100.100.5
    100.100.100.6


From CSV file:

    2012-10-01,100.100.100.1,random comments
    2012-10-01,100.100.100.2,random comments
    2012-10-01,100.100.100.3,random comments
    2012-10-01,100.100.100.4,random comments
    2012-10-01,100.100.100.5,random comments
    2012-10-01,100.100.100.6,random comments

To create threats:

    ocd-dtl add_threats -o output_file.json -tt ddos 50 scam 15 -i ip_list.txt -at IP --tag test0 test32 test320 

    ocd-dtl add_threats -o output_file.json -tt ddos 50 scam 15 -i ip_list.csv -at IP --tag test0 test32 test320 --is-csv -d , -c 2

### Parameters

#### Specific command's parameters
Required:
* `-i, --input <INPUT_PATH>` : path of the file containing the threats (atom) values
* `-at, --atom-type <ATOM_TYPE>` : atom type, in our example it is IP 

Use either:
* `-tt, --threat-types <THREATTYPE1 SCORE1 THREATTYPE2 SCORE2 [...]>` : threat types and its associated score like: ddos 50 scam 15 (see below for the authorized values).  Default is no score set for any type
* `-w, --whitelist` : will set all the scores to 0 like a whitelist. Overrides -tt 


Optional flags:
* `--no-bulk` force an api call for each threats, useful to retrieve the details of the threats created. If a large number of threats has to be created and this flag is set, there is a risk of failure. Please make sure to use this flag only when creating a limited number of threats.
* `-t, --tag <TAG1 TAG2 [...]>` : will add all the following tags to the new threats
* `-p, --public` : will set the visibility to public. Default is **organization**  
* `--is-csv` flag is required if your input file is a csv file.  
* `-d, --delimiter <DELIMITER>` : custom delimiter for the input csv file. Default is **,**
* `-c, --column` : column number to select the column containing the threats' values in the input csv file (starting at **1**)  
* `--link` : link i.e. an URL that will be filled in "external_analysis_link"  
* `--lock` : will set override_type to lock. For scores that should not be updated by the algorithm during three months . Default value for override_type is **temporary**


Currently the results outputted with `-o, --output` (Common parameter, see below) depends on the API endpoints call:
* If `--no-bulk` isn't set, the output file will contain a json with the hashkey and the value of the threats created. If some threats failed to be created, the value and the hashkey will be recorded in the json.
* If `--no-bulk` is set, the output file will contain a json with all the details about the created threats.

#### Common parameters
Common parameters for all commands:  
* `-e, --env <preprod|prod>` :   Datalake environment. Default is **prod**  
* `-o, --output <OUTPUT_PATH>` : will set the output file as the API gives it.  No default
* `-D, --debug`  : will raise the verbosity of the program (by displaying additional DEBUG messages). Default log level is INFO
* `-q, --quiet` : will quiet the verbosity of the program (but will still show ERROR / WARNING messages). Default log level is INFO

#### Accepted threat types

for `-tt, --threat-types` parameter, please use values from list below:  

    ddos
    fraud
    hack
    leak
    malware
    phishing
    scam
    scan
    spam

Followed by a number between 0 and 100

### Environment variables

For the bulk mode, the following environment variable can be used 

* `OCD_DTL_MAX_BACK_OFF_TIME` allow to set the maximum time period to wait between two api 
calls to check if the bulk submission is complete.  Default is **120** seconds.
* `OCD_DTL_MAX_BULK_THREATS_TIME` is the maximum time period, in seconds, to wait for the manual submission to be processed, 
after which the threats will be considered not successfully added. Default is **600** seconds.
* `OCD_DTL_MAX_BULK_THREATS_IN_FLIGHT` is the maximum bulk requests made in parallel, 
increasing this value may result in your personal queue limit to be reached. Default is **10**.