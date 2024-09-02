# Get atom values from their source id and time range

#### Examples

From TXT file `sources_id.txt`:

    a
    b
    c

To retrieve them:
    
    ocd-dtl get_atom_values --input sources_id.txt -o output.json --since "2023-09-14T15:00:00.000Z" --until "2023-09-15T15:12:13.825Z" -e preprod

Or directly from the cli:
    
    ocd-dtl get_atom_values a b c -o output.json -ot json --since "2023-09-14" --until "2023-09-15"

### Parameters

#### Specific command's parameters

Required :

Use Either :
* `<SOURCE_ID1 SOURCE_ID2 [...]>` : (positional argument) the source id(s)  
* `-i, --input <INPUT_PATH>` : input file containing the source id(s)  

At least one of them is required.  
If both parameters are provided, only source id(s) in the file will be retrieved. 

Also required :
* `--since`  
* `--until`  

Both parameters create the timestamp range for the search  
Two format are accepted :  
Normalized timestamps: "%Y-%m-%dT%H:%M:%S.%f[:3]Z"  
or   
Dates : "%Y-%m-%d" (in that case, the hour "00:00:00.000" will be used for the since parameter while the hour "23:59:59.999" will be used for the until parameter so that both dates are included in the search)

Optional : 
* `-ot, --output-type <json|csv>` : file output type. Default is **json**   

#### Common parameters
Common parameters for all commands:  
* `-e, --env <preprod|prod>` :   Datalake environment. Default is **prod**  
* `-o, --output <OUTPUT_PATH>` : will set the output file as the API gives it.  No default
* `-D, --debug`  : will raise the verbosity of the program (by displaying additional DEBUG messages). Default log level is INFO
* `-q, --quiet` : will quiet the verbosity of the program (but will still show ERROR / WARNING messages). Default log level is INFO
