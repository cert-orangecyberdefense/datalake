# Add new threats

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

    add_new_threats -o output_file.json -t ddos 50 scam 15 -i ip_list.txt -a IP --tag test0 test32 test320 
    add_new_threats -o output_file.json -t ddos 50 scam 15 -i ip_list.csv -a IP --tag test0 test32 test320 --is_csv -d , -c 1

Options:

> -i will be the input file  
> -a will set the atom type, here IP

> -t will set the score for the threat to the corresponding value, here you have `ddos = 50` and `scam = 15`  
> -w (Optional) will set all the scores to 0 like a whitelist  
> --tag will add all the following tags to the new threats, here `test0 test32 test320`

>  (Optional)  
> --is_csv  set it to have a csv file as an input  
> -d to have a special delimiter  
> -c to select the column (starting at **1**)

> -o (Optional) will set the output file as the API gives it.  
> -q (Optional) will quiet the verbosity of the program (but still show errors / warnings)  
> -e (Optional) to change the environment {preprod, prod},  default is **prod**  
> -p (Optional) set the visibility to public default=private 

