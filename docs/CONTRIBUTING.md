# Contribute

## Adding a new script

To add a new script, simply create a new file in `./src/scripts/{my_script_name.py}`.
Add the following line in `./setup.py`:
```
    entry_points={
        'console_scripts': (
        {my_script_name} = src.scripts.{my_script_name}:main,
        xxxxxxxxxxxxxxxx = src.scripts.xxxxxxxxxxxxxxxx:main,
        )
    }
```
And add a new function to the [cli file](src/cli.py).
  
> You will need to reinstall your environement by running `pipenv install`.