## CLI Usage

```bash
ocd-dtl get_filtered_tag_subcategory [OPTIONS]
```

### Options

All arguments are optional

The following options are available to refine your query. All options are optional, and each one corresponds to a field in the `TagSubcategoryFilteredRequest` model:

- `--alias`: A string to filter the list by the alias of the tag subcategory. Must be at least 1 character long.
- `--category_name`: A string to specify the name of the category for which subcategories need to be retrieved, please note that this argument is case-sensitive.
- `--description`: A string to filter the list by the description of the tag subcategory. Must be at least 1 character long.
- `--limit`: An integer defining the maximum number of items to return, with a default of 10 and a maximum of 5000.
- `--name`: A string to filter by the name of the tag subcategory. Must be at least 1 character long.
- `--offset`: An integer defining the index of the first item to return, with a default of 0.
- `--ordering`: A string specifying the ordering of the results, with a default of `category_name`. Accepts one of the predefined values in the array.
- `--stix_uuid`: A string to filter by the STIX UUID of the tag subcategory. Must be at least 1 character long.
- `--tag`: A string to filter by the tag associated with the subcategory. Must be at least 1 character long.

Each option is used to refine your search and sort the data returned by the Datalake API. Use these options to customize the output based on your requirements.
### Getting the Results

Use the `ocd-dtl get_filtered_tag_subcategory` command with the desired options to retrieve and filter the list of tag subcategories.

For example:

```bash
ocd-dtl get_filtered_tag_subcategory --category_name malware --limit 10 --output malware_subcategories.json
```

This command will retrieve the first 10 subcategories for the 'malware' category and save them in a file named `malware_subcategories.json`.
## Additional Resources
- [Datalake API Documentation](https://datalake.cert.orangecyberdefense.com/api/v2/docs/)