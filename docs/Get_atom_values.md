# Get atom values from their source id and time range

#### Examples

From TXT file `sources_id.txt`:

    a
    b
    c

To retrieve them:
    
    ocd-dtl get_atom_values --input_file sources_id.txt -o output.json --since "2023-09-14T15:00:00.000Z" --until "2023-09-15T15:12:13.825Z" -e preprod

Or directly from the cli:
    
    ocd-dtl get_atom_values a b c -o output.json -ot json --since "2023-09-14" --until "2023-09-15"

#### Parameters

> <source_id\> (positional argument) the source id(s)  
> -i, --input_file will be the input file containg the source id(s)  

At least one of them is required.  
If both parameters are provided, only source id(s) in the file will be retrieved. 

> --since  
> --until  

Both parameters represent the timestamp range for the search  
Two format are accepted :  
Normalized timestamps: "%Y-%m-%dT%H:%M:%S.%f[:3]Z"  
or   
Dates : "%Y-%m-%d" (in that case, the hour "00:00:00.000" will be used for the since parameter while the hour "23:59:59.999" will be used for the until parameter so that both dates are included in the search)

> -ot, --output_type (Optional) sets the output type desired {json, csv}. Default is json  
> -o (Optional) will set the output file as the API gives it. Default is no output file created  
> -e (Optional) to change the environment {preprod, prod}. Default is **prod**  