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

    from datalake-scripts import Datalake
    datalake = Datalake()

## About the parameters

# Authentication
In case you don't want to enter credential for each commands and you are on a secured terminal, set those variables:  
* `OCD_DTL_USERNAME` email address used to login on Datalake API/GUI.   
* `OCD_DTL_PASSWORD` password used to login on Datalake API/GUI.
> They are independent and one can be used without the other if you wish.

then declare an instance of that class with your credentials
datalake = Datalake(username, password)

### Usage: Code Sample

    import os
    from datalake_scripts import Datalake

    datalake = Datalake(username=os.getenv('OCD_DTL_USERNAME'),
                        password=os.getenv('OCD_DTL_PASSWORD'))

## lookup a threat in api

please note that the parameters atom_type and hashkey_only are optional.

    datalake.lookup_threat(
        threat = 'mayoclinic.org',
        atom_type = 'domain',
        hashkey_only = False,
    )

or also: 
    datalake.lookup_threat(threat)

## Bulk look up
# Use to look up threats in api

    threats = [
        'mayoclinic.org',
        'commentcamarche.net',
        'gawker.com'
    ]
    atom_type = 'domain'
    hashkey_only = False

    datalake.bulk_lookup_threats(threats, atom_type, hashkey_only)
or also :
    datalake.bulk_lookup_threats(threats)


