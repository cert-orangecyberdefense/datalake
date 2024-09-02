# Get threats from a query hash

This command allows to retrieve all threats at once without having to deal with a pagination.  

> You need to have bulk search permission to use this endpoint  
You can see your set of permission on the [GUI](https://datalake.cert.orangecyberdefense.com/gui/my-account)  
Or on the [API](https://datalake.cert.orangecyberdefense.com/api/v3/users/me/) using this endpoint: /v3/users/me/

#### Examples

To retrieve hashkeys as a list :
    
    ocd-dtl get_threats_from_query_hash 4e26a3d4bbfd87375d04aaef983b6c8a --list -o output.text

Will respond by:
```
b7980ce58188a221abe23548826e9a1b
43f6b78e3b80397633d46a6207c1c6ec
61994647e96ef289342e288d3fc366ff
```

Or make a more advanced query, that will return directly the API response (using json format):
    
    ocd-dtl get_threats_from_query_hash 46b384ce467f4d2ae8b74025f9b266ed --query-fields atom_value .android.developer .android.permissions -o output.json

> For atoms details, keep in mind to prefix them with a **dot** like for .android.developer   
If no value is present, an empty string will replace it
### Parameters

#### Specific command's parameters
Required:
* `<QUERY_HASH|PATH_QUERY_BODY>` : (positional argument) **query hash** or a valid local path to a (json) file (containing a **query body** instead)

Optional:
* `--query-fields <FIELD1 FIELD2 [...]` : fields to be retrieved from the threat. Default is **threat_hashkey**  
* `--list` : will turn the output to a list (this requires query_fields to be **a single element**) 

#### Common parameters
Common parameters for all commands:  
* `-e, --env <preprod|prod>` :   Datalake environment. Default is **prod**  
* `-o, --output <OUTPUT_PATH>` : will set the output file as the API gives it.  No default
* `-D, --debug`  : will raise the verbosity of the program (by displaying additional DEBUG messages). Default log level is INFO
* `-q, --quiet` : will quiet the verbosity of the program (but will still show ERROR / WARNING messages). Default log level is INFO

### Environment variables

* `OCD_DTL_MAX_BACK_OFF_TIME` allow to set the maximum time period to wait between two api 
calls to check if the bulk search is ready.  Default is **120** seconds.
* `OCD_DTL_MAX_BULK_SEARCH_TIME`, the maximum time period, in seconds, to wait for the bulksearch to be ready, 
after which the bulk search will be considered failed. Default is **3600** seconds.