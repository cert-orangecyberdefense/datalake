# Get threat(s) from their hashkeys

#### Examples

From TXT file `hashkeys.txt`:

    9f1a0af65610adc5cf10159f0413c499
    afca2b3539110c70f53755e4eae5b4d6
    88d277709c94fe4380de77b974ac0c14

To retrieve them:
    
    ocd-dtl get_threats --input hashkeys.txt -o output.json

Or directly from the cli:
    
    ocd-dtl get_threats 9f1a0af65610adc5cf10159f0413c499 afca2b3539110c70f53755e4eae5b4d6 88d277709c94fe4380de77b974ac0c14 -o output.json

### Parameters

#### Specific command's parameters
Required:

Use either:
* `<HASHKEY1 HASHKEY2 [...]>` : (positional argument) haskey(s) to query  
* `-i, --input <INPUT_PATH>` : path of the input file containing the haskeys to query 

At least one of them is required.  
If both parameters are provided, only hashkeys in the file will be retrieved. 

Optional:
* `--lost`: path of the output file that will contain the haskeys that were not found


#### Common parameters
Common parameters for all commands:  
* `-e, --env <preprod|prod>` :   Datalake environment. Default is **prod**  
* `-o, --output <OUTPUT_PATH>` : will set the output file as the API gives it.  No default
* `-D --debug`  : will raise the verbosity of the program (by displaying additional DEBUG messages). Default log level is INFO
* `-q, --quiet` : will quiet the verbosity of the program (but will still show ERROR / WARNING messages). Default log level is INFO
