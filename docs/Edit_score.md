# Edit the score of existing threats from their hashkeys

#### Examples

From TXT file `hashkeys.txt`:

    9f1a0af65610adc5cf10159f0413c499
    afca2b3539110c70f53755e4eae5b4d6
    88d277709c94fe4380de77b974ac0c14

To edit them:
    
    ocd-dtl edit_score -i input.txt -o output.json -t malware 90 scam 12

Or directly from the cli:
    
    ocd-dtl edit_score 9f1a0af65610adc5cf10159f0413c499 afca2b3539110c70f53755e4eae5b4d6 88d277709c94fe4380de77b974ac0c14 -t malware 90 scam 12

#### Parameters

> <hashkeys\> (positional argument) the haskeys to edit   
> -i will be the input file  

At least one of them is required.  

> -t the list of threat types and it's associated score like: ddos 50 scam 15 (see below for the authorized values).

> -o (Optional) will set the output file as the API gives it.  
> -e (Optional) to change the environment {preprod, prod},  default is **prod**  

#### Accepted threat types

for -t parameter, please use one of:  

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
