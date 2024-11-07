# Advanced Search

### Examples

#### With a query body
To execute an advanced search from a query body stocked in a json file.

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
ocd-dtl advanced_search -i query_body.json -o output.json
````
#### With a query hash
To execute an advanced search from a query hash run the following command.
````
ocd-dtl advanced_search --query-hash cece3117abc823cee81e69c2143e6268 -o output.json
````

#### Parameters

#### Specific command's parameters

Required : 

Use either:
* `-i, --input <INPUT_PATH>` : path of the input file containing the query body
* `-qh, --query-hash <QUER_HASH>` : query hash for your advanced search

Optional:
* `-l, --limit` : number of items returned in one page slice. Accepted values: 0 to 5000. Default is **20**
* `--offset` : defines an index of the first requested item. Accepted values: 0 and bigger, default is 0
* `-ot, --output-type <json|csv|stix|misp>` : desired output type . Default is **json**
* `--ordering <<|->ORDER>` : threat field to filter on. To sort the results by relevance (if any "search" is applied), just skip this field. To use the reversed order, use minus, i.e. `--ordering="-last_updated"`.

#### Common parameters
Common parameters for all commands:  
* `-e, --env <preprod|prod>` :   Datalake environment. Default is **prod**  
* `-o, --output <OUTPUT_PATH>` : will set the output file as the API gives it.  No default
* `-D, --debug`  : will raise the verbosity of the program (by displaying additional DEBUG messages). Default log level is INFO
* `-q, --quiet` : will quiet the verbosity of the program (but will still show ERROR / WARNING messages). Default log level is INFO
