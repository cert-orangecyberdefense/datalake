     ____        _        _       _         
    |  _ \  __ _| |_ __ _| | __ _| | _____  
    | | | |/ _` | __/ _` | |/ _` | |/ / _ \ 
    | |_| | (_| | || (_| | | (_| |   <  __/  
    |____/ \__,_|\__\__,_|_|\__,_|_|\_\___| 
                                        
# Use this package as a Python library
Using this library has multiple advantages, it first allows you to get started more quickly than by using the API directly.
The library is also maintained directly by the developers of Datalake thus reducing the burden of keeping it compatible with the API over time.
Finally, as it is open-source, you can reuse the functionalities developed by other Datalake users as well as helps improve this package further yourself.

### step 1: install datalake

With Python 3.6+:  
```
$ pip install datalake-scripts
or
$ pip3 install datalake-scripts
```

### step 2: Create a Datalake instance
You will need to create a Datalake instance once and reuse it:
```python
from datalake import Datalake
dtl = Datalake(username='username', password='password')
```
The credentials can be omitted and will then be asked in a prompt.  
You can also set them in your os environment variables:
* `OCD_DTL_USERNAME` email address used to login on Datalake API/GUI.   
* `OCD_DTL_PASSWORD` password used to login on Datalake API/GUI.

## Usage: Code Sample
Below are some examples to get you started
### lookup a threat
```python
from datalake import AtomType, Output
dtl.Threats.lookup(
    atom_value='mayoclinic.org',
    atom_type=AtomType.DOMAIN,
    hashkey_only=False,
    output=Output.JSON,
)
```

Note that only the atom_value is required:

    dtl.Threats.lookup(threat)

### Bulk look up
Compared to the lookup, the bulk_lookup method allows to lookup big batch of values faster as fewer API calls are made.  
However, fewer outputs types are supported (only json and csv as of now).
```python
from datalake import AtomType, Output

threats = [
    'mayoclinic.org',
    'commentcamarche.net',
    'gawker.com'
]

dtl.Threats.bulk_lookup(
    atom_values=threats, 
    atom_type=AtomType.DOMAIN,
    hashkey_only=False,
    output=Output.CSV,
    return_search_hashkey=False
)
```

### Bulk search
A convenient download_sync method is provided:
```python
task = dtl.BulkSearch.create_task(query_hash='<some query hash>')
csv = task.download_sync(output=Output.CSV)
```
The following Output format are available:
* JSON
* JSON_ZIP
* CSV
* CSV_ZIP
* STIX
* STIX_ZIP

The STIX and STIX_ZIP format are **only** available if when creating the task it is specified that it is for stix export, using the `for_stix_export` parameter

```python
task = dtl.BulkSearch.create_task(for_stix_export=True, query_hash='<some query hash>')
stix = task.download_sync(output=Output.STIX)
```

Depending of your use case, you can call an async version to parallelize the wait of bulk search for example:
```python
# Queuing multiple bulk searches at once saves a lot of time
# However you will receive HTTP 400 error if you try to enqueue too many bulk search at once (more than 10)
query_hashes_to_process = [
    '7018d41944b71b04a9d3785b3741c842',
    '207d02c81edde3c87f665451f04f9bd1',
    '9f7a8fecb0a74e508d6873c4d6e0d614',
    '8bd8f1b47ce1a76ac2a1dc9e91aa9a5e',
    'd3f8e2006554aaffa554714c614acd30',
]
coroutines = []
for query_hash in query_hashes_to_process:
    task = dtl.BulkSearch.create_task(query_hash=query_hash)
    coroutines.append(task.download_async(output=Output.JSON))

loop = asyncio.get_event_loop()
future = asyncio.gather(*coroutines)
results = loop.run_until_complete(future)

result_per_query_hash = {}  # Since results keep its order, we can easily attach back query_hash to its result
for query_hash, result in zip(query_hashes_to_process, results):
    result_per_query_hash[query_hash] = result
print(result_per_query_hash)

# will output:
{
    "query_hash_1": {"result of query_hash 1"},
    "query_hash_2": {"result of query_hash 2"},
    ...
}
```

### Add threat
The library provides a convenient way to add threats.
You can call the `add_threat` function the following way:
```python
from datalake import ThreatType, OverrideType, AtomType

atom_list = ['01.01.111.1', '01.01.111.2']
threat_types = [{'threat_type': ThreatType.DDOS, 'score': 0}]
dtl.Threats.add_threats(atom_list, AtomType.IP, threat_types, OverrideType.TEMPORARY, public=False)
```
The following positional arguments are required:
* `atom_list`: a List of strings. Contains the list of threats to add. In our example it's a list of IPs.
* `atom_type`: an AtomType. Available options are: **APK, AS, CC, CRYPTO, CVE, DOMAIN, EMAIL, FILE, FQDN, IBAN, IP, IP_RANGE, PATE, PHONE_NUMBER, REGKEY, SSL, URL**

The following keyword arguments are available:
* `threat_types`: A list of dictionaries containing a key named `threat_type` with a `ThreatType` value and a key named `score` with an integer value between **0** and **100**. Available ThreatType options are: **DDOS, FRAUD, HACK, LEAK, MALWARE, PHISHING, SCAM, SCAN, SPAM**. Defaults to `None`.
 * `override_type`: an OverrideType. Available options are:
    * `PERMANENT`: All values will override any values provided by both newer and
older IOCs. Newer IOCs with override_type permanent can still override old permanent changes.
    * `TEMPORARY`: All values should override any values provided by older IOCs,
but not newer ones.
    * `LOCK`: Will act like a permanent for three months,
then like a temporary.
* `whitelist`: A boolean, if no `threat_types` are provided, this argument should be set to true. All score values will then be set to 0. If `threat_types` are provided along with `whitelist` set as `True`, will result in an error. Defaults to `False`.
* `public`: A boolean, sets whether the threats should be public or private. Defaults to `True`.
* `tags`: a List of strings. Will set the tags of the added threat(s).
* `external_analysis_link`: a List of strings. A link to an external resource providing more information about the threat.
* `no_bulk`: A boolean, wheter to execute a bulk creation or not. Should be set to `True` if your are adding a large number of threats. Defaults to `False`.

Depending on whether `no_bulk` is set to `True` or not, the response provided by the library will be different.
When `no_bulk` is to `True`, the return value will be a list of the details of the created threats. When it is set to `False`, the return value will be a list of dictionaries for each bulk request, containing the hashkeys and values of the threats created as well as the hashkeys and values of the threats that failed to be created when it's the case.

### Add tags
A quick and easy way to add tags to a threat
```python
hashkey = '00000001655688982ec8ba4058f02dd1'
tags = ['green', 'white']
public = False

dtl.Tags.add_to_threat(hashkey, tags, public)
```

### Edit score
Mutliple threats can be edited at once, each threat type independently:
```python
from datalake import ThreatType

hashkeys = [
    '00000001655688982ec8ba4058f02dd1',
    '00000001655688982ec8ba4058f02dd2',
]
threat_scores_list = [
    {'threat_type': ThreatType.DDOS, 'score': 5},
    {'threat_type': ThreatType.PHISHING, 'score': 25},
]
override_type = OverrideType.TEMPORARY

dtl.Threats.edit_score_by_hashkeys(hashkeys, threat_scores_list, override_type)
```
Query hashes can also be used with another function provided for that use:
```python
from datalake import ThreatType, OverrideType

query_body_hash = '7018d41944b71b04a9d3785b3741c842'
threat_scores_list = [
    {'threat_type': ThreatType.DDOS, 'score': 5},
    {'threat_type': ThreatType.PHISHING, 'score': 25},
]
override_type = OverrideType.TEMPORARY

dtl.Threats.edit_score_by_query_body_hash(query_body_hash, threat_scores_list, override_type)
```

### Advanced Search
The library can be used to execute advanced search if you have a query hash or a query to body, using `advanced_search_from_query_hash` or `advanced_search_from_query_body`  .
````python
from datalake.common.ouput import Output

query_body = {
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
query_hash = 'cece3117abc823cee81e69c2143e6268'

adv_search_hash_resp = dtl.AdvancedSearch.advanced_search_from_query_hash(query_hash, limit=20, offset=0, 
                                                                          ordering='first_seen', output=Output.JSON)

adv_search_body_resp = dtl.AdvancedSearch.advanced_search_from_query_body(query_bodylimit=20, offset=0, 
                                                                          ordering='-first_seen', output=Output.JSON)
````
### Sightings
Sightings can be submitted using the library using a list of atoms:
```python
from datalake import IpAtom, EmailAtom, UrlAtom, FileAtom, Hashes, SightingType, Visibility, ThreatType

hashes = Hashes(md5='your_md5_hashes')
f1 = FileAtom(hashes=hashes)
ip1 = IpAtom('8.8.8.8')
em1 = EmailAtom('hacker@hacker.ha')
url1 = UrlAtom('http://notfishing.com')

threat_types = [ThreatType.PHISHING, ThreatType.SCAM]
start = (datetime.fromtimestamp(1620656423)).strftime("%Y-%m-%dT%H:%M:%SZ")
end = (datetime.fromtimestamp(1620742823)).strftime("%Y-%m-%dT%H:%M:%SZ")

resp = dtl.Sightings.submit_sighting(start, end, SightingType.POSITIVE, Visibility.PUBLIC, 1, threat_types, atoms=[ip1, f1, em1, url1])
```
Or using a list of hashkeys:
```python
from datalake.common.atom_type import IpAtom, EmailAtom, UrlAtom, Atom
from datalake.common.atom import SightingType, Visibility, ThreatType

threat_types = [ThreatType.PHISHING, ThreatType.SCAM]
start = (datetime.datetime.utcnow()).strftime("%Y-%m-%dT%H:%M:%SZ")
end = (datetime.datetime.utcnow() - datetime.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")

resp = dtl.Sightings.submit_sighting(start, end, SightingType.POSITIVE, Visibility.PUBLIC, 1, threat_types, hashkeys=['mythreathashkeys'])
```
The atom_type file provides multiple classes to build each type of atom type used by the API. The classes will provide you with hints on the value expected for each atom_type, must of which aren't mandatory.
For sightings, we won't use most of the fields. You can verify the fields that are used for sighting in the docstrings of each class, inside of your editor.


### API documentation
For more information on the API used by this library, see [the documentation](https://datalake.cert.orangecyberdefense.com/api/v2/docs/)
