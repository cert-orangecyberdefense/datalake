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
Required:
* `-o` : indicate the output file's path

Use either:
* `-i` : indicate the path of the file containing the query body
* `--query-hash` : the query hash for your advanced search

Optional flags:
* `--limit` : defines how many items will be returned in one page slice. Accepted values: 0 to 5000, default is 20
* `--offset` : defines an index of the first requested item. Accepted values: 0 and bigger, default is 0
* `--output-type` : sets the output type desired {json, csv, stix, misp}. Default is json
* `--ordering` : threat field to filter on. To sort the results by relevance (if any "search" is applied), just skip this field. To use the reversed order, use minus, i.e. `--ordering="-last_updated"`.