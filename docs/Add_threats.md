# Add new threats

#### Examples

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

    ocd-dtl add_threats -o output_file.json -t ddos 50 scam 15 -i ip_list.txt -a IP --tag test0 test32 test320 
    ocd-dtl add_threats -o output_file.json -t ddos 50 scam 15 -i ip_list.csv -a IP --tag test0 test32 test320 --is_csv -d , -c 2

#### Parameters
Required:
* `-i` : indicate the file path 
* `-a` : indicate the atom type, in our example it is IP 

Use either:
* `-t` : will set the score for the threat to the corresponding value. In our example we set `ddos = 50` and `scam = 15`. Can be ignored if the next paramaeter, `-w`, is set.
* `-w` : If `-t` is not set this flag is required. Will set all the scores to 0 to whitelist the threat.


Optional flags:
* `--no-bulk` force an api call for each threats, useful to retrieve the details of the threats created. If a large number of threats has to be created and this flag is set, there is a risk of failure. Please make sure to use this flag only when creating a limited number of threats.
* `--tag` will add all the following tags to the new threats, in our example `test0 test32 test320`  
* `-p` set the visibility to public. Default is private  
* `--is_csv` flag is required if your input file is a csv file.  
* `-d` to specify a custom delimiter  
* `-c` to select the starting column (starting at **1**)  
* `--link` to provide a link i.e. a URL that will be filled in "external_analysis_link"  
* `--permanent` to set override_type to permanent. For scores that should not be updated by the algorithm  
* `-o` will set the output file as the API gives it*.  
* `-e` to change the environment {preprod, prod},  default is **prod**   


Currently the result outputted with `-o` depends on the API endpoints call:
* If `--no-bulk` isn't set, the output file will contain a json with the hashkey and the value of the threats created. If some threats failed to be created, the value and the hashkey will be recorded in the json.
* If `--no-bulk` is set, the output file will contain a json with all the details about the created threats.

### Environment variables

For the bulk mode, the following environment variable can be used 

* `OCD_DTL_MAX_BACK_OFF_TIME` allow to set the maximum time period to wait between two api 
calls to check if the bulk submission is complete.  *default is 120 seconds*.
* `OCD_DTL_MAX_BULK_THREATS_TIME` is the maximum time period, in seconds, to wait for the manual submission to be processed, 
after which the threats will be considered not successfully added. *default is 600 seconds*.
* `OCD_DTL_MAX_BULK_THREATS_IN_FLIGHT` is the maximum bulk requests made in parallel, 
increasing this value may result in your personal queue limit to be reached. *default is 10*.