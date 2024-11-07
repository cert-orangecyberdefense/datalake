## Get tag subcategories

```bash
ocd-dtl get_filtered_tag_subcategory [OPTIONS]
```

### Getting the Results

Use the `ocd-dtl get_filtered_tag_subcategory` command with the desired parameters to retrieve and filter the list of tag subcategories.

### Examples

```bash
ocd-dtl get_filtered_tag_subcategory --category-name Malware --limit 10 --output malware_subcategories.json
```

This command will retrieve the first 10 subcategories for the 'Malware' category and save them in a file named `malware_subcategories.json`.

### Parameters

#### Specific command's parameters

The following parameters are available to refine your query. All parameters are optional, and each one corresponds to a field in the `TagSubcategoryFilteredRequest` model:

- `--alias <STRING>`: string to filter the list by the alias of the tag subcategory. Must be at least 1 character long.
- `--category-name <STRING>`: string to specify the name of the category for which subcategories need to be retrieved, please note that this argument is case-sensitive.
- `--description <STRING>`: string to filter the list by the description of the tag subcategory. Must be at least 1 character long.
- `-l, --limit <INT>`: integer defining the maximum number of items to return, with a default of 10 and a maximum of 5000.
- `--name <STRING>`: string to filter by the name of the tag subcategory. Must be at least 1 character long.
- `--offset <INT>`: integer defining the index of the first item to return, with a default of 0.
- `--stix_uuid <STRING>`: string to filter by the STIX UUID of the tag subcategory. Must be at least 1 character long.
- `-t, --tag <STRING>`: string to filter by the tag associated with the subcategory. Must be at least 1 character long.
- `--ordering <STRING>`: string specifying the ordering of the results. Accepts one of the predefined values in the array. Default is **category_name**

Each paraemter is used to refine your search and sort the data returned by the Datalake API. Use these parameters to customize the output based on your requirements.

#### Common parameters
Common parameters for all commands:  
* `-e, --env <preprod|prod>` :   Datalake environment. Default is **prod**  
* `-o, --output <OUTPUT_PATH>` : will set the output file as the API gives it.  No default
* `-D, --debug`  : will raise the verbosity of the program (by displaying additional DEBUG messages). Default log level is INFO
* `-q, --quiet` : will quiet the verbosity of the program (but will still show ERROR / WARNING messages). Default log level is INFO

