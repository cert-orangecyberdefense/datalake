     ____        _        _       _         
    |  _ \  __ _| |_ __ _| | __ _| | _____  
    | | | |/ _` | __/ _` | |/ _` | |/ / _ \ 
    | |_| | (_| | || (_| | | (_| |   <  __/  
    |____/ \__,_|\__\__,_|_|\__,_|_|\_\___| 
                                        
### step 1: install datalake

With Python 3.6+:  
```
$ pip install datalake-scripts
$ pip3 install datalake-scripts
```

### step 2: Create a Datalake instance
Usually you create a Datalake instance in your main module or in the __init__.py file of your package like this:
```python
from datalake import Datalake
datalake = Datalake()
```

## About the parameters

# Authentication
In case you don't want to enter credential for each commands and you are on a secured terminal, set those variables:  
* `OCD_DTL_USERNAME` email address used to login on Datalake API/GUI.   
* `OCD_DTL_PASSWORD` password used to login on Datalake API/GUI.
> They are independent and one can be used without the other if you wish.

then declare an instance of that class with your credentials
datalake = Datalake(username, password)

### Usage: Code Sample
```python
from datalake import Datalake

datalake = Datalake(username='username', password='password')
```

## lookup a threat in api
```python
datalake.Threats.lookup(
    threat='mayoclinic.org',
    atom_type=AtomType.DOMAIN,
    hashkey_only=False,
)
```

please note that atom_type and hashkey_only parameters are optional:

    datalake.Threats.lookup(threat)

## Bulk look up
```python
from datalake import AtomType, Output

threats = [
    'mayoclinic.org',
    'commentcamarche.net',
    'gawker.com'
]


datalake.Threats.bulk_lookup(
    threats, 
    atom_type=AtomType.DOMAIN,
    hashkey_only=False,
    output=Output.CSV
)
```


