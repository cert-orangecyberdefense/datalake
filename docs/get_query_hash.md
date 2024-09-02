# Retrieve a query hash from a query body (a json used to perform an Advanced Search)

#### Example

Given a query body stocked in a json file.

`query_body.json`
````
{
  "AND": [
    {
      "AND": [
        {
          "field": "atom_type",
          "multi_values": [
            "ip"
          ],
          "type": "filter"
        },
        {
          "field": "risk",
          "range": {
            "gt": 60
          },
          "type": "filter"
        }
      ]
    }
  ]
}
````
Run the following command
````
ocd-dtl get_query_hash query_body.json -o output.json
````
to retrieve the corresponding query_hash

#### Parameters

#### Specific command's parameters

Required :
* `<INPUT_PATH>` : (positional argument) path to the json file containing the query body 

#### Common parameters
Common parameters for all commands:  
* `-e, --env <preprod|prod>` :   Datalake environment. Default is **prod**  
* `-o, --output <OUTPUT_PATH>` : will set the output file as the API gives it.  No default
* `-D, --debug`  : will raise the verbosity of the program (by displaying additional DEBUG messages). Default log level is INFO
* `-q, --quiet` : will quiet the verbosity of the program (but will still show ERROR / WARNING messages). Default log level is INFO