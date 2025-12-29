## Get threat entities

```bash
ocd-dtl get_filtered_threat_entity [OPTIONS]
```

### Getting the Results

Use the `ocd-dtl get_filtered_threat_entity` command with the desired parameters to retrieve and filter the list of threat entities.

### Examples

```bash
ocd-dtl get_filtered_threat_entity --threat-category-name Malware --limit 10 --output malware_threat_entities.json
```

This command will retrieve the first 10 threat entities for the 'Malware' threat category and save them in a file named `malware_threat_entities.json`.

### Parameters

#### Specific command's parameters

The following parameters are available to refine your query. All parameters are optional, and each one corresponds to a field in the `ThreatEntityFilteredRequest` model:

- `--alias <STRING>`: string to filter the list by the alias of the threat entity. Must be at least 1 character long.
- `--threat-category-name <STRING>`: string to specify the name of the threat_category for which threat entities need to be retrieved, please note that this argument is case-sensitive.
- `--description <STRING>`: string to filter the list by the description of the threat entity. Must be at least 1 character long.
- `-l, --limit <INT>`: integer defining the maximum number of items to return, with a default of 10 and a maximum of 5000.
- `--name <STRING>`: string to filter by the name of the threat entity. Must be at least 1 character long.
- `--offset <INT>`: integer defining the index of the first item to return, with a default of 0.
- `--stix_uuid <STRING>`: string to filter by the STIX UUID of the threat entity. Must be at least 1 character long.
- `-t, --tag <STRING>`: string to filter by the tag associated with the threat entity. Must be at least 1 character long.
- `--ordering <STRING>`: string specifying the ordering of the results. Accepts one of the predefined values in the array. Default is **threat_category_name**
* `-ot, --output-type <json|stix>` : desired output type. Default is **json**

Each paraemter is used to refine your search and sort the data returned by the Datalake API. Use these parameters to customize the output based on your requirements.

#### Common parameters
Common parameters for all commands:  
* `-e, --env <preprod|prod>` :   Datalake environment. Default is **prod**  
* `-o, --output <OUTPUT_PATH>` : will set the output file as the API gives it.  No default
* `-D, --debug`  : will raise the verbosity of the program (by displaying additional DEBUG messages). Default log level is INFO
* `-q, --quiet` : will quiet the verbosity of the program (but will still show ERROR / WARNING messages). Default log level is INFO

