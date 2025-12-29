# Edit the score of existing threat(s) from their hashkeys

#### Examples

From TXT file `hashkeys.txt`:

    9f1a0af65610adc5cf10159f0413c499
    afca2b3539110c70f53755e4eae5b4d6
    88d277709c94fe4380de77b974ac0c14

To edit them:
    
    ocd-dtl edit_score -i input.txt -o output.json -tt malware 90 scam 12

Or directly from the cli:
    
    ocd-dtl edit_score 9f1a0af65610adc5cf10159f0413c499 afca2b3539110c70f53755e4eae5b4d6 88d277709c94fe4380de77b974ac0c14 -tt malware 90 scam 12

#### Parameters

#### Specific command's parameters

Required :

Use either:
* `<HASHKEY1 HASHKEY2 [...]>` : (positional argument) haskey(s) to query   
* `-i, --input <INPUT_PATH>` : path of the input file containing the haskeys to edit 

Optional:
* `-tt, --threat-types <THREATTYPE1 SCORE1 THREATTYPE2 SCORE2 [...]>` : threat types and its associated score like: ddos 50 scam 15 (see below for the authorized values).  Default is no score set for any type
* `-w, --whitelist` : will set all the scores to 0 like a whitelist. Overrides -tt  

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

The following environment variable can be used 

* `OCD_DTL_MAX_EDIT_SCORE_HASHKEYS` Sets the number of hashkeys that can be edited with one function call. Default is 100.