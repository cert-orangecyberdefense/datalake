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

### Parameters

#### Specific command's parameters
Required:

Use either:
* `-i, --input <INPUT_PATH>` : path of the json file containing the query body
* `-qh, --query-hash <QUERY_HASH>` : query hash for your search watch

Optional:
* `-of, --output-folder <OUTPUT_FOLDER_PATH>` : output folder where the results json files will be stored. It is also uses as the folder to lookup in when filename (`-f, --filename`) for comparison is not provided. Default value for this parameter is the local directory.
* `-f, --filename <FILENAME>` : reference file which will be used as base of comparison. Default is the latest file in the output folder (`--ouput-folder, -of`) that is taken.  
* `-sdt, --save-diff-threats` : will create a file `<queryhashkey>-diff_threats-<timestamp>.json` containing added and removed threats. 

#### Common parameters
Common parameters for all commands:  
* `-e, --env <preprod|prod>` :   Datalake environment. Default is **prod**  
* `-o, --output <OUTPUT_PATH>` : will set the output file as the API gives it.  No default
* `-D, --debug`  : will raise the verbosity of the program (by displaying additional DEBUG messages). Default log level is INFO
* `-q, --quiet` : will quiet the verbosity of the program (but will still show ERROR / WARNING messages). Default log level is INFO
