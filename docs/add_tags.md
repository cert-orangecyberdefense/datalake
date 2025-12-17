# Add tag(s) to existing threats from their hashkeys

#### Example

From TXT file `hashkeys.txt`:

    9f1a0af65610adc5cf10159f0413c499
    afca2b3539110c70f53755e4eae5b4d6
    88d277709c94fe4380de77b974ac0c14

To add a comment them:
    
    ocd-dtl add_tags -i input.txt -o output.json --tag amazing_tag malicious_tag

Or directly from the cli:
    
    ocd-dtl add_tags 9f1a0af65610adc5cf10159f0413c499 afca2b3539110c70f53755e4eae5b4d6 88d277709c94fe4380de77b974ac0c14 -t amazing_tag malicious_tag

#### Parameters

#### Specific command's parameters

Required :

Use either:
* `<HASHKEY1 HASHKEY2 [...]>` : (positional argument) haskeys to query   
* `-i, --input <INPUT_PATH>` : path of the input file containing the haskeys to edit 

Also required:
* `-t, --tag <TAG1 TAG2 [...]>` : tag(s) to add

Optional:
* `-p, --public` : will set the visibility to public. Default is **organization** 

#### Common parameters
Common parameters for all commands:  
* `-e, --env <preprod|prod>` :   Datalake environment. Default is **prod**  
* `-o, --output <OUTPUT_PATH>` : will set the output file as the API gives it.  No default
* `-D, --debug`  : will raise the verbosity of the program (by displaying additional DEBUG messages). Default log level is INFO
* `-q, --quiet` : will quiet the verbosity of the program (but will still show ERROR / WARNING messages). Default log level is INFO


