# Returns wether or not a threat (atom value) is in the Datalake database

#### Examples

From TXT file `input.txt`:

    threat1.com
    anotherthreat.fr
    en.wikipedia

From CSV file:

    #comment
    2012-10-01,threat1.com,random comments
    2012-10-01,anotherthreat.fr,random comments
    2012-10-01,en.wikipedia,random comments

To look them up:
    
    ocd-dtl lookup_threats -i input.txt -o output.csv -ot csv -a domain

Or/And directly from the cli:
    
    ocd-dtl lookup_threats threat1.com anotherthreat.fr en.wikipedia -o output.json -a domain


### Parameters

#### Specific command's parameters

Required:

* `-at, --atom-type <ATOM_TYPE>` : atom type of the threats

Use either:

* `<THREAT1 THREAT2 [...]>` : (positional argument) threats to lookup   
* `-i, --input <INPUT_PATH>` : path of the input file containing the threats to lookup 



Optional:
* `--is-csv` :  will indicate the input file is a csv file   
* `-d, --delimiter <DELIMITER>` :  delimiter of the input csv file. Default is **,**
* `-c, --column <INT>` : column number of the input csv file containing the threats values (numbers starting at **1**). Default is **1**
* `-ot, --output-type <json|csv>` : output file type. Default is **json**
* `-td, --threat-details` : will also return the threats' details 
 


#### Common parameters
Common parameters for all commands:  
* `-e, --env <preprod|prod>` :   Datalake environment. Default is **prod**  
* `-o, --output <OUTPUT_PATH>` : will set the output file as the API gives it.  No default
* `-D, --debug`  : will raise the verbosity of the program (by displaying additional DEBUG messages). Default log level is INFO
* `-q, --quiet` : will quiet the verbosity of the program (but will still show ERROR / WARNING messages). Default log level is INFO
