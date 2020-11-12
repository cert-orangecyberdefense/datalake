# Returns wether or not a threat is in the database

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


#### Parameters

> <atoms\> (positional argument) the threats to lookup   
> -i will be the input file  
> -a will set the atom type, here domain

>  (Optional)  
> --is_csv  set it to have a csv file as an input  
> -d to have a special delimiter  
> -c to select the column (starting at **1**)
> -ho set it to False to get the complete result
> -ot set it to json or csv to choose the output type. Default is json
> -td, --threat_details set if you also want to have access to the threat details in output file
> -o (Optional) will set the output file as a csv.  
> -e (Optional) to change the environment {preprod, prod},  default is **prod**  
