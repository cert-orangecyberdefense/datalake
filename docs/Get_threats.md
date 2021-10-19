# Get threats from their hashkeys

#### Examples

From TXT file `hashkeys.txt`:

    9f1a0af65610adc5cf10159f0413c499
    afca2b3539110c70f53755e4eae5b4d6
    88d277709c94fe4380de77b974ac0c14

To retrieve them:
    
    ocd-dtl get_threats --input_file hashkeys.txt -o output.json

Or directly from the cli:
    
    ocd-dtl get_threats 9f1a0af65610adc5cf10159f0413c499 afca2b3539110c70f53755e4eae5b4d6 88d277709c94fe4380de77b974ac0c14 -o output.json

#### Parameters

> <hashkeys\> (positional argument) the haskeys to query   
> -i will be the input file  

At least one of them is required.  
If both parameters are provided, only hashkeys in the file will be retrieved. 

> -o (Optional) will set the output file as the API gives it.  
> -e (Optional) to change the environment {preprod, prod},  default is **prod**  
