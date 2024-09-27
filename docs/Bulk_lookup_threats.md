# Returns whether threats are in the database or not

### Using input files
This command can read one or multiple files at the same time as atom input. To pass them, using `-i` or `--input` 
argument followed by the relative or absolute path.

You can pass files as typed or untyped, it means that you will indicate which kind of atoms are inside the files.
* **typed files**: `<ATOM_TYPE>:<FILE_PATH>`  
  Here, the command will expect that each line represents a single atom of given type. For example, the following file 
  contains only domains.
  ```
  threat1.com
  anotherthreat.fr
  en.wikipedia
  ```
  
* **untyped files**: `<FILE_PATH>`  
  Here, the command will determinate line by line the atom type. For example, the following file contains multiple 
  atom types.
  ```
  discover.me
  f0f5d30e91006c8ca7a528f26432ftt5
  113.223.40.103
  ```

  ```shell
  $ ocd-dtl bulk_lookup_threats -i ip:path/to/file/myiplist.txt -i file:path/to/file/myfilelist.txt
                                  --------- ip typed ---------    --------- file typed -----------
                                  
  $ ocd-dtl bulk_lookup_threats -i path/to/file/myatomlist.txt
                                  --------- untyped ---------
  ```

### Passing atoms by CLI
As input files, you can pass one or multiple **typed** or **untyped** atoms by CLI.

* **typed atoms**: Each atom has its own flag called exactly the same as the atom type.
  ```shell
  $ ocd-dtl bulk_lookup_threats --ip 113.223.40.103 --ip 5.78.23.158 --domain reverso.net  --file f0f5d30e91006c8ca7a528f26432ftt5 
  ```     

* **untyped atoms**: If you don't know the atom type, pass them as positional arguments, and the command will find out its type. 
  ```shell
  $ ocd-dtl bulk_lookup_threats 113.223.40.103 5.78.23.158 reverso.net f0f5d30e91006c8ca7a528f26432ftt5 
  ```     
  

With all that in mind, you can combine them to fit your needs:
```shell
$ ocd-dtl bulk_lookup_threats reverso.net 113.223.40.103 --domain paiza.com --ip 45.96.65.132 -i ip:path/to/file/myiplist.txt -i path/to/file/myfilelist.txt
                             ----untyped domain ip----- ---typed domain--- ----typed ip----  -------typed file as ip-------- ---------untyped file---------                                                
```

    
### Parameters

* Optional arguments
    > -h, --help   
    show this help message and exit

    > -o [OUTPUT], --output [OUTPUT]  
    file path from script

    > -ot OUTPUT_TYPE, --output-type OUTPUT_TYPE  
    set to the output type desired {json,csv}. Default is json
  
    > -e {prod,preprod}, --env {prod,preprod}     
    execute on specified environment (Default: prod)

    > --debug
  
    > -q, --quiet  
    Silence the output to only show warnings/errors
  
    > -ad, --atom-details  
    returns threats full details
   
    > -i INPUT, --input INPUT  
    read threats to add from FILE.

    > -s, --score : Specify the minimum score for an atom to be considered.

    > --date : Specify the earliest date from which atoms should be included. [format: YYYY-MM-DD]
   
* Typed atom flags
    > --apk APK             
    --asn ASN             
    --cc CC               
    --crypto CRYPTO       
    --cve CVE             
    --domain DOMAIN       
    --email EMAIL         
    --file FILE           
    --fqdn FQDN           
    --iban IBAN           
    --ip IP               
    --ip_range IP_RANGE   
    --paste PASTE         
    --phone_number PHONE_NUMBER  
    --regkey REGKEY
    --ssl SSL
    --url URL