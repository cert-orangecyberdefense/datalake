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
    ocd-dtl add_threats -o output_file.json -t ddos 50 scam 15 -i ip_list.csv -a IP --tag test0 test32 test320 --is_csv -d , -c 1

#### Parameters
Required:
> -i will be the input file  
> -a will set the atom type, here IP 

> -t will set the score for the threat to the corresponding value, here you have `ddos = 50` and `scam = 15`  
> -w (Optional) will set all the scores to 0 like a whitelist  


(Optional) 
> --no-bulk force an api call for each threats, useful to retrieve the details of threats created
> --tag will add all the following tags to the new threats, here `test0 test32 test320`  
> -p set the visibility to public default=private  
> --is_csv  set it to have a csv file as an input  
> -d to have a special delimiter  
> -c to select the column (starting at **1**)  
> --link to provide a link i.e. a URL that will be filled in "external_analysis_link"  
> --permanent to set override_type to permanent. For scores that should not be updated by the algorithm  
> -o will set the output file as the API gives it*.  
> -e to change the environment {preprod, prod, dtl2},  default is **prod**   


*Currently the result outputted with `-o` depends on the API endpoints call:
* The bulk one will only return the hashkeys of the created threats. This is the default behavior.
* The classic one will return all the details about created threats. This endpoint can be forced with the option `--no-bulk`

### Environment variables

For the bulk mode, the following environment variable can be used 

* `OCD_DTL_MAX_BACK_OFF_TIME` allow to set the maximum time period to wait between two api 
calls to check if the bulk submission is complete.  *default is 120 seconds*.
* `OCD_DTL_MAX_BULK_THREATS_TIME` is the maximum time period, in seconds, to wait for the manual submission to be processed, 
after which the threats will be considered not successfully added. *default is 600 seconds*.
* `OCD_DTL_MAX_BULK_THREATS_IN_FLIGHT` is the maximum bulk requests made in parallel, 
increasing this value may result in your personal queue limit to be reached. *default is 10*.