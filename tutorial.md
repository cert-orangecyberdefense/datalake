     ____        _        _       _         
    |  _ \  __ _| |_ __ _| | __ _| | _____  
    | | | |/ _` | __/ _` | |/ _` | |/ / _ \ 
    | |_| | (_| | || (_| | | (_| |   <  __/  
    |____/ \__,_|\__\__,_|_|\__,_|_|\_\___| 
                                        
# Use this package as a Python library
Using this library has multiple advantages, it first allows you to get started more quickly than by using the API directly.
The library is also maintained directly by the developers of Datalake thus reducing the burden of keeping it compatible with the API over time.
Finally, as it is open-source, you can reuse the functionnalities developed by other Datalake users as well as helps improve this package further yourself.

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
You can also set them in your os environnement variables:
* `OCD_DTL_USERNAME` email address used to login on Datalake API/GUI.   
* `OCD_DTL_PASSWORD` password used to login on Datalake API/GUI.

## Usage: Code Sample
Below are some examples to get you started
### lookup a threat
```python
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
    output=Output.CSV
)
```

### Bulk search
A convenient download_sync method is provided:
```python
task = dtl.BulkSearch.create_task(query_hash='<some query hash>')
csv = task.download_sync(output=Output.CSV)
```

But depending of your use case, you can call an async version to parallelize the wait of bulk search for example:
```python
# Queuing multiple bulk searches at once saves a lot of time
# However you will receive HTTP 400 error if you try to enqueue too many bulk search at once (more than 10)
query_hashes_to_process = [
    'eb40e5cdd6f640708c8bbe640ac2d10a',
    'de70393f1c250ae67566ec37c2032d1b',
    '850557fefb053cb9aefd858084e5ccb7',
    '0740b2dd87c55737d68f898e9a63adbd',
    '55682bb7d762428c324880e220328ecf',
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

