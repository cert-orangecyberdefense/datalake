# Search Watch

It is possible to monitor (watch) a search to find new iocs that match your search criteria, through the **search_watch** CLI.

### Examples

#### With a query body
To execute a search watch from a query body stocked in a json file.

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
ocd-dtl search_watch -i query_body.json -of /tmp/search_watch
````
#### With a query hash
To execute an search watch from a query hash, run the following command.
````
ocd-dtl search_watch --query-hash cece3117abc823cee81e69c2143e6268 -of /tmp/search_watch
````

#### Sample ouput

```
Threats summary from 2023-11-10 17:30:00 to 2023-11-12 17:06:04:
Number of added items: 3
Number of removed items: 1

+----------------------------------------------------+---------------------------------------------------+
|           Added (atom value - hash key)            |          Removed (atom value - hash key)          |
+----------------------------------------------------+---------------------------------------------------+
| 0.0.0.0 - 71a390d5e6e2d44c4674d1841d69cc34         | 1.192.0.0 - 88a390d5e6e2d44c46d4d1841d69cc34      |
| 1.1.1.1 - 521c6a0110a260497d767b3f95fe59c7         |                         -                         |
| 2.2.2.2 - 020c9281d0d93a76cc86ab87cda13a06         |                         -                         |
+----------------------------------------------------+---------------------------------------------------+
```

#### Parameters
Required:

Use either:
* `-i` : indicates the path of the file containing the query body
* `--query-hash` : the query hash for your search watch

Optional flags:
* `-of` : indicates the output folder where the results json files will be stored. It is also uses as the folder to lookup in when filename (-f) for comparison is not provided. The default value for this parameter is the local directory.
* `--filename` : defines the reference file which will be used as base of comparison. By default it is the latest file in the directory (given by `-of` or the default local directory) that is taken.  
* `--save-diff-threats` : If sets, will create a file `<queryhashkey>-diff_threats-<timestamp>.json` containing added and removed threats.