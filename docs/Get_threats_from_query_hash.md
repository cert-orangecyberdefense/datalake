# Get threats from a query hash

This command allow to retrieve all threats at once without having to deal with a pagination.  

> You need to have bulk search permission to use this endpoint  
You can see your set of permission on the [GUI](https://datalake.cert.orangecyberdefense.com/gui/my-account)  
Or on the [API](https://datalake.cert.orangecyberdefense.com/api/v1/users/me/) using this endpoint: /v1/users/me/

#### Examples

To retrieve hashkeys as a list :
    
    ocd-dtl get_threats_from_query_hash 4e26a3d4bbfd87375d04aaef983b6c8a --list -o output.text

Will respond by:
```
b7980ce58188a221abe23548826e9a1b
43f6b78e3b80397633d46a6207c1c6ec
61994647e96ef289342e288d3fc366ff
```

Or make a more advanced query, that will return directly the API response (using json format):
    
    ocd-dtl get_threats_from_query_hash 46b384ce467f4d2ae8b74025f9b266ed --query_fields atom_value .android.developer .android.permissions -o output.json

> For atoms details, keep in mind to prefix them with a **dot** like for .android.developer   
If no value is present, an empty string will replace it
#### Parameters

> <query_hash\> (positional argument) the query_hash to query   

> --query_fields (Optional) fields to be retrieved from the threat (default: threat_hashkey)  
> --list (Optional)  Turn the output in a list (require query_fields to be **a single element**)

> -o (Optional) will set the output file as the API gives it.  
> -e (Optional) to change the environment {preprod, prod},  default is **prod**  
